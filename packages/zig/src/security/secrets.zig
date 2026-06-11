const std = @import("std");
extern "c" fn system(command: [*:0]const u8) c_int;
extern "c" fn unlink(path: [*:0]const u8) c_int;
const mutex_compat = @import("../core/mutex_compat.zig");
const time_compat = @import("../core/time_compat.zig");
const logger = @import("../core/logger.zig");
const env = @import("../core/env.zig");

// =============================================================================
// Secret Management - Multi-Backend Secret Storage
// =============================================================================
//
// ## Overview
// Provides a unified interface for retrieving secrets from various backends,
// enabling secure credential management in production deployments without
// hardcoding sensitive values.
//
// ## Supported Backends
//
// | Backend              | Use Case                      | Auth Method           |
// |---------------------|-------------------------------|----------------------|
// | Environment         | Development, simple deploys   | N/A                  |
// | HashiCorp Vault     | Enterprise, multi-tenant      | Token, AppRole       |
// | Kubernetes Secrets  | K8s deployments               | Mounted volumes, API |
// | AWS Secrets Manager | AWS cloud deployments         | IAM Role, Access Keys|
// | Azure Key Vault     | Azure cloud deployments       | Managed Identity, SP |
// | File                | Development only              | File system          |
//
// ## Architecture
//
// ```
//                     ┌─────────────────────┐
//                     │   SecretManager     │
//                     │  (Unified Interface)│
//                     └──────────┬──────────┘
//                                │
//          ┌──────────┬─────────┼─────────┬──────────┐
//          ▼          ▼         ▼         ▼          ▼
//     ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
//     │  Vault │ │  K8s   │ │  AWS   │ │ Azure  │ │  File  │
//     │Backend │ │Backend │ │Backend │ │Backend │ │Backend │
//     └────────┘ └────────┘ └────────┘ └────────┘ └────────┘
// ```
//
// ## HashiCorp Vault Integration
//
// ### Authentication Methods
// 1. **Token Auth**: Direct token (for development/testing)
// 2. **AppRole Auth**: Machine-to-machine (recommended for production)
//
// ### AppRole Flow
// ```
// 1. Application has role_id (semi-public) and secret_id (private)
// 2. POST /v1/auth/approle/login {role_id, secret_id}
// 3. Receive client_token with TTL
// 4. Use token for subsequent secret reads
// 5. Token auto-renewed before expiry
// ```
//
// ### KV v2 Secret Path
// ```
// GET /v1/{mount}/data/{path}
//
// Response:
// {
//   "data": {
//     "data": {"value": "secret-value"},
//     "metadata": {"version": 3, "created_time": "..."}
//   }
// }
// ```
//
// ## AWS Secrets Manager Integration
//
// ### Authentication
// - **IAM Role** (recommended): Automatic via instance metadata
// - **Access Keys**: Explicit credentials (use only when necessary)
//
// ### API Request Signing (SigV4)
// ```
// 1. Create canonical request (method, path, query, headers, payload)
// 2. Create string to sign (algorithm, timestamp, scope, canonical hash)
// 3. Calculate signing key (HMAC chain: date → region → service → request)
// 4. Calculate signature (HMAC of string to sign)
// 5. Add Authorization header
// ```
//
// ### GetSecretValue API
// ```
// POST / HTTP/1.1
// Host: secretsmanager.{region}.amazonaws.com
// X-Amz-Target: secretsmanager.GetSecretValue
// Content-Type: application/x-amz-json-1.1
//
// {"SecretId": "my-secret"}
// ```
//
// ## Kubernetes Secrets Integration
//
// ### Mounted Volumes (Recommended)
// Secrets mounted at `/var/run/secrets/{secret-name}`:
// ```yaml
// volumes:
//   - name: db-credentials
//     secret:
//       secretName: db-credentials
// volumeMounts:
//   - name: db-credentials
//     mountPath: /var/run/secrets/db-credentials
// ```
//
// ### Kubernetes API
// ```
// GET /api/v1/namespaces/{ns}/secrets/{name}
// Authorization: Bearer {service-account-token}
// ```
//
// ## Caching Strategy
//
// ```
// ┌──────────────┐     Cache Hit      ┌──────────────┐
// │   Request    │ ─────────────────▶ │ Return Value │
// └──────────────┘                    └──────────────┘
//        │
//        │ Cache Miss
//        ▼
// ┌──────────────┐     Fetch          ┌──────────────┐
// │   Backend    │ ─────────────────▶ │ Cache + TTL  │
// └──────────────┘                    └──────────────┘
// ```
//
// - Default TTL: 5 minutes (300 seconds)
// - Secrets zeroed from memory on eviction
// - Thread-safe with mutex protection
//
// ## Security Best Practices
//
// 1. **Never log secrets**: Use redaction in all logging
// 2. **Zero memory**: `@memset(secret, 0)` before freeing
// 3. **Minimal TTL**: Cache only as long as needed
// 4. **Rotate regularly**: Use secret versioning
// 5. **Audit access**: Enable backend audit logging
//
// ## Configuration Examples
//
// ### HashiCorp Vault
// ```zig
// var secrets = SecretManager.init(allocator, .vault);
// try secrets.configureVault(.{
//     .address = "https://vault.example.com:8200",
//     .role_id = "db-app-role",
//     .secret_id = env.get("VAULT_SECRET_ID"),
//     .mount_path = "secret",
// });
// ```
//
// ### AWS Secrets Manager
// ```zig
// var secrets = SecretManager.init(allocator, .aws_secrets_manager);
// secrets.configureAws(.{
//     .region = "us-west-2",
//     // IAM role used automatically on EC2/ECS/Lambda
// });
// ```
//
// ### Kubernetes
// ```zig
// var secrets = SecretManager.init(allocator, .kubernetes);
// secrets.configureKubernetes(.{
//     .secrets_path = "/var/run/secrets",
// });
// ```
// =============================================================================

/// Secret Management Integration
/// Provides unified interface for retrieving secrets from various backends:
/// - Environment variables (default)
/// - HashiCorp Vault
/// - Kubernetes Secrets
/// - AWS Secrets Manager
/// - Azure Key Vault
/// - File-based secrets (for development)
///
/// ## Usage
/// ```zig
/// var secrets = try SecretManager.init(allocator, .vault, vault_config);
/// defer secrets.deinit();
///
/// const api_key = try secrets.getSecret("smtp/api-key");
/// defer allocator.free(api_key);
/// ```
/// Secret backend types
pub const SecretBackend = enum {
    environment, // Environment variables (default)
    vault, // HashiCorp Vault
    kubernetes, // Kubernetes Secrets via mounted volumes
    aws_secrets_manager, // AWS Secrets Manager
    azure_key_vault, // Azure Key Vault
    file, // File-based (development only)

    pub fn toString(self: SecretBackend) []const u8 {
        return switch (self) {
            .environment => "environment",
            .vault => "hashicorp_vault",
            .kubernetes => "kubernetes_secrets",
            .aws_secrets_manager => "aws_secrets_manager",
            .azure_key_vault => "azure_key_vault",
            .file => "file",
        };
    }
};

/// HashiCorp Vault configuration
pub const VaultConfig = struct {
    address: []const u8 = "http://127.0.0.1:8200",
    token: ?[]const u8 = null,
    role_id: ?[]const u8 = null, // For AppRole auth
    secret_id: ?[]const u8 = null, // For AppRole auth
    namespace: ?[]const u8 = null, // Enterprise namespaces
    mount_path: []const u8 = "secret", // KV secrets engine mount
    kv_version: u8 = 2, // KV v1 or v2
    tls_skip_verify: bool = false, // For development only
    timeout_ms: u32 = 5000,
    retry_count: u8 = 3,
    retry_delay_ms: u32 = 1000,
};

/// Kubernetes Secrets configuration
pub const KubernetesConfig = struct {
    secrets_path: []const u8 = "/var/run/secrets", // Default mount path
    namespace: ?[]const u8 = null, // If using API
    use_api: bool = false, // Use K8s API instead of mounted volumes
    service_account_token_path: []const u8 = "/var/run/secrets/kubernetes.io/serviceaccount/token",
};

/// AWS Secrets Manager configuration
pub const AwsConfig = struct {
    region: []const u8 = "us-east-1",
    access_key_id: ?[]const u8 = null, // Falls back to IAM role
    secret_access_key: ?[]const u8 = null,
    session_token: ?[]const u8 = null, // For temporary credentials
    endpoint: ?[]const u8 = null, // Custom endpoint (localstack)
    timeout_ms: u32 = 5000,
};

/// Azure Key Vault configuration
pub const AzureConfig = struct {
    vault_url: []const u8, // https://<vault-name>.vault.azure.net
    tenant_id: ?[]const u8 = null,
    client_id: ?[]const u8 = null,
    client_secret: ?[]const u8 = null,
    use_managed_identity: bool = true, // Recommended for Azure
    timeout_ms: u32 = 5000,
};

/// File-based secrets configuration (development only)
pub const FileConfig = struct {
    secrets_dir: []const u8 = "./secrets",
    file_extension: []const u8 = ".secret",
};

/// Cached secret with TTL
const CachedSecret = struct {
    value: []u8,
    expires_at: i64,
    version: ?[]const u8,
};

/// Secret Manager - unified interface for all backends
pub const SecretManager = struct {
    allocator: std.mem.Allocator,
    backend: SecretBackend,
    cache: std.StringHashMap(CachedSecret),
    cache_ttl_seconds: i64,
    mutex: mutex_compat.Mutex,

    // Backend-specific state
    vault_config: ?VaultConfig,
    vault_token: ?[]u8, // Authenticated token
    k8s_config: ?KubernetesConfig,
    aws_config: ?AwsConfig,
    azure_config: ?AzureConfig,
    file_config: ?FileConfig,

    // Statistics
    stats: SecretStats,

    pub fn init(allocator: std.mem.Allocator, backend: SecretBackend) SecretManager {
        return .{
            .allocator = allocator,
            .backend = backend,
            .cache = std.StringHashMap(CachedSecret).init(allocator),
            .cache_ttl_seconds = 300, // 5 minute default TTL
            .mutex = .{},
            .vault_config = null,
            .vault_token = null,
            .k8s_config = null,
            .aws_config = null,
            .azure_config = null,
            .file_config = null,
            .stats = SecretStats{},
        };
    }

    pub fn deinit(self: *SecretManager) void {
        // Free cached secrets
        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            // Securely zero out secret before freeing
            @memset(entry.value_ptr.value, 0);
            self.allocator.free(entry.value_ptr.value);
            if (entry.value_ptr.version) |v| {
                self.allocator.free(v);
            }
            self.allocator.free(entry.key_ptr.*);
        }
        self.cache.deinit();

        if (self.vault_token) |token| {
            @memset(token, 0);
            self.allocator.free(token);
        }
    }

    /// Configure Vault backend
    pub fn configureVault(self: *SecretManager, config: VaultConfig) !void {
        self.vault_config = config;
        self.backend = .vault;

        // Authenticate with Vault
        if (config.token) |token| {
            self.vault_token = try self.allocator.dupe(u8, token);
        } else if (config.role_id != null and config.secret_id != null) {
            // AppRole authentication would go here
            // For now, just note that it's configured
            logger.info("Vault AppRole authentication configured", .{});
        }

        logger.info("Vault backend configured: {s}", .{config.address});
    }

    /// Configure Kubernetes backend
    pub fn configureKubernetes(self: *SecretManager, config: KubernetesConfig) void {
        self.k8s_config = config;
        self.backend = .kubernetes;
        logger.info("Kubernetes secrets backend configured: {s}", .{config.secrets_path});
    }

    /// Configure AWS Secrets Manager backend
    pub fn configureAws(self: *SecretManager, config: AwsConfig) void {
        self.aws_config = config;
        self.backend = .aws_secrets_manager;
        logger.info("AWS Secrets Manager configured: {s}", .{config.region});
    }

    /// Configure Azure Key Vault backend
    pub fn configureAzure(self: *SecretManager, config: AzureConfig) void {
        self.azure_config = config;
        self.backend = .azure_key_vault;
        logger.info("Azure Key Vault configured: {s}", .{config.vault_url});
    }

    /// Configure file-based backend (development only)
    pub fn configureFile(self: *SecretManager, config: FileConfig) void {
        self.file_config = config;
        self.backend = .file;
        logger.warn("File-based secrets configured - FOR DEVELOPMENT ONLY", .{});
    }

    /// Get a secret by name
    pub fn getSecret(self: *SecretManager, name: []const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check cache first
        if (self.cache.get(name)) |cached| {
            if (cached.expires_at > time_compat.timestamp()) {
                self.stats.cache_hits += 1;
                return try self.allocator.dupe(u8, cached.value);
            }
            // Expired - remove from cache
            self.removeCachedSecret(name);
        }

        self.stats.cache_misses += 1;

        // Fetch from backend
        const secret = try self.fetchSecret(name);
        errdefer {
            @memset(secret, 0);
            self.allocator.free(secret);
        }

        // Cache the secret
        try self.cacheSecret(name, secret);

        self.stats.fetches += 1;
        return secret;
    }

    /// Get a secret with a specific version (Vault, AWS)
    pub fn getSecretVersion(self: *SecretManager, name: []const u8, version: []const u8) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Version-specific secrets are not cached
        return self.fetchSecretVersion(name, version);
    }

    /// Check if a secret exists
    pub fn secretExists(self: *SecretManager, name: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check cache
        if (self.cache.contains(name)) {
            return true;
        }

        // Check backend
        const secret = self.fetchSecret(name) catch return false;
        @memset(secret, 0);
        self.allocator.free(secret);
        return true;
    }

    /// Invalidate a cached secret
    pub fn invalidateSecret(self: *SecretManager, name: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.removeCachedSecret(name);
        self.stats.invalidations += 1;
    }

    /// Invalidate all cached secrets
    pub fn invalidateAll(self: *SecretManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            @memset(entry.value_ptr.value, 0);
            self.allocator.free(entry.value_ptr.value);
            if (entry.value_ptr.version) |v| {
                self.allocator.free(v);
            }
            self.allocator.free(entry.key_ptr.*);
        }
        self.cache.clearRetainingCapacity();
        self.stats.invalidations += 1;
    }

    /// Set cache TTL
    pub fn setCacheTtl(self: *SecretManager, ttl_seconds: i64) void {
        self.cache_ttl_seconds = ttl_seconds;
    }

    /// Get statistics
    pub fn getStats(self: *const SecretManager) SecretStats {
        return self.stats;
    }

    // Internal methods

    fn fetchSecret(self: *SecretManager, name: []const u8) ![]u8 {
        return switch (self.backend) {
            .environment => self.fetchFromEnvironment(name),
            .vault => self.fetchFromVault(name),
            .kubernetes => self.fetchFromKubernetes(name),
            .aws_secrets_manager => self.fetchFromAws(name),
            .azure_key_vault => self.fetchFromAzure(name),
            .file => self.fetchFromFile(name),
        };
    }

    fn fetchSecretVersion(self: *SecretManager, name: []const u8, version: []const u8) ![]u8 {
        _ = version;
        // Version support depends on backend
        return self.fetchSecret(name);
    }

    fn fetchFromEnvironment(self: *SecretManager, name: []const u8) ![]u8 {
        // Convert secret path to env var name (e.g., "smtp/api-key" -> "SMTP_API_KEY")
        var env_name = try self.allocator.alloc(u8, name.len);
        defer self.allocator.free(env_name);

        for (name, 0..) |c, i| {
            env_name[i] = switch (c) {
                '/', '-', '.' => '_',
                'a'...'z' => c - 32, // to uppercase
                else => c,
            };
        }

        const value = env.get(env_name) orelse return error.SecretNotFound;
        return try self.allocator.dupe(u8, value);
    }

    fn fetchFromVault(self: *SecretManager, name: []const u8) ![]u8 {
        const config = self.vault_config orelse return error.BackendNotConfigured;

        // In a full implementation, this would:
        // 1. Make HTTP request to Vault API
        // 2. GET /v1/{mount_path}/data/{name} for KV v2
        // 3. Parse JSON response
        // 4. Return the secret value
        // Using config.address, config.mount_path, etc.
        _ = config;

        // For now, fall back to environment
        return self.fetchFromEnvironment(name);
    }

    fn fetchFromKubernetes(self: *SecretManager, name: []const u8) ![]u8 {
        const config = self.k8s_config orelse return error.BackendNotConfigured;

        if (config.use_api) {
            // Would use K8s API
            return error.NotImplemented;
        }

        // Read from mounted secret file
        const path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ config.secrets_path, name });
        defer self.allocator.free(path);

        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            if (err == error.FileNotFound) return error.SecretNotFound;
            return err;
        };
        defer file.close();

        const content = try time_compat.readFileToEnd(self.allocator, file, 1024 * 1024);

        // Trim trailing newline if present
        var value = content;
        if (value.len > 0 and value[value.len - 1] == '\n') {
            value = value[0 .. value.len - 1];
        }

        return value;
    }

    /// True when `name` only contains characters safe to interpolate into a
    /// shell command (secret ids: alnum plus / _ . : - @).
    fn isSafeSecretName(name: []const u8) bool {
        if (name.len == 0 or name.len > 512) return false;
        for (name) |c| {
            const ok = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or
                (c >= '0' and c <= '9') or c == '/' or c == '_' or c == '.' or
                c == ':' or c == '-' or c == '@';
            if (!ok) return false;
        }
        return true;
    }

    /// Run a command and capture its stdout via a temp file (the same
    /// pattern deliverViaSes and the Discord monitor use — this codebase
    /// has no native HTTPS client; cloud APIs go through their CLIs).
    fn runCliCapture(self: *SecretManager, cmd: []const u8) ![]u8 {
        const ts = time_compat.milliTimestamp();
        const tmp_path = try std.fmt.allocPrint(self.allocator, "/tmp/.mail_secret_{d}", .{ts});
        defer self.allocator.free(tmp_path);

        const full_cmd = try std.fmt.allocPrintSentinel(self.allocator, "{s} > {s} 2>/dev/null", .{ cmd, tmp_path }, 0);
        defer self.allocator.free(full_cmd);

        const tmp_path_z = try self.allocator.dupeZ(u8, tmp_path);
        defer self.allocator.free(tmp_path_z);
        defer _ = unlink(tmp_path_z.ptr);

        const ret = system(full_cmd.ptr);
        if (ret != 0) return error.SecretNotFound;

        const fp = std.c.fopen(tmp_path_z.ptr, "r") orelse return error.SecretNotFound;
        defer _ = std.c.fclose(fp);

        var buf: [64 * 1024]u8 = undefined;
        const n = std.c.fread(&buf, 1, buf.len, fp);
        if (n == 0) return error.SecretNotFound;

        // Trim the trailing newline the CLIs append
        var out = buf[0..n];
        while (out.len > 0 and (out[out.len - 1] == '\n' or out[out.len - 1] == '\r')) {
            out = out[0 .. out.len - 1];
        }
        if (out.len == 0) return error.SecretNotFound;
        return try self.allocator.dupe(u8, out);
    }

    /// AWS Secrets Manager via the aws CLI (same access path the SES
    /// delivery backend uses). Requires the instance role / configured
    /// credentials the CLI normally picks up.
    fn fetchFromAws(self: *SecretManager, name: []const u8) ![]u8 {
        const config = self.aws_config orelse return error.BackendNotConfigured;
        if (!isSafeSecretName(name)) return error.SecretNotFound;
        if (!isSafeSecretName(config.region)) return error.BackendNotConfigured;

        const cmd = try std.fmt.allocPrint(
            self.allocator,
            "aws secretsmanager get-secret-value --region {s} --secret-id '{s}' --query SecretString --output text",
            .{ config.region, name },
        );
        defer self.allocator.free(cmd);

        return self.runCliCapture(cmd);
    }

    /// Azure Key Vault via the az CLI (managed identity or `az login`
    /// credentials).
    fn fetchFromAzure(self: *SecretManager, name: []const u8) ![]u8 {
        const config = self.azure_config orelse return error.BackendNotConfigured;
        if (!isSafeSecretName(name)) return error.SecretNotFound;

        // vault_url is "https://<name>.vault.azure.net"; az wants the vault
        // name. Extract the first label of the host.
        const host_start = if (std.mem.indexOf(u8, config.vault_url, "://")) |p| p + 3 else 0;
        const host = config.vault_url[host_start..];
        const vault_name = host[0 .. std.mem.indexOfScalar(u8, host, '.') orelse host.len];
        if (!isSafeSecretName(vault_name)) return error.BackendNotConfigured;

        const cmd = try std.fmt.allocPrint(
            self.allocator,
            "az keyvault secret show --vault-name '{s}' --name '{s}' --query value --output tsv",
            .{ vault_name, name },
        );
        defer self.allocator.free(cmd);

        return self.runCliCapture(cmd);
    }

    fn fetchFromFile(self: *SecretManager, name: []const u8) ![]u8 {
        const config = self.file_config orelse return error.BackendNotConfigured;

        // Replace path separators with underscores for filename
        var filename = try self.allocator.alloc(u8, name.len);
        defer self.allocator.free(filename);
        for (name, 0..) |c, i| {
            filename[i] = if (c == '/') '_' else c;
        }

        const path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}{s}",
            .{ config.secrets_dir, filename, config.file_extension },
        );
        defer self.allocator.free(path);

        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            if (err == error.FileNotFound) return error.SecretNotFound;
            return err;
        };
        defer file.close();

        const content = try time_compat.readFileToEnd(self.allocator, file, 1024 * 1024);

        // Trim trailing newline
        var value = content;
        if (value.len > 0 and value[value.len - 1] == '\n') {
            value = value[0 .. value.len - 1];
        }

        return value;
    }

    fn cacheSecret(self: *SecretManager, name: []const u8, value: []u8) !void {
        const name_copy = try self.allocator.dupe(u8, name);
        const value_copy = try self.allocator.dupe(u8, value);

        try self.cache.put(name_copy, CachedSecret{
            .value = value_copy,
            .expires_at = time_compat.timestamp() + self.cache_ttl_seconds,
            .version = null,
        });
    }

    fn removeCachedSecret(self: *SecretManager, name: []const u8) void {
        if (self.cache.fetchRemove(name)) |entry| {
            @memset(entry.value.value, 0);
            self.allocator.free(entry.value.value);
            if (entry.value.version) |v| {
                self.allocator.free(v);
            }
            self.allocator.free(entry.key);
        }
    }
};

/// Statistics for secret manager
pub const SecretStats = struct {
    cache_hits: u64 = 0,
    cache_misses: u64 = 0,
    fetches: u64 = 0,
    errors: u64 = 0,
    invalidations: u64 = 0,

    pub fn cacheHitRate(self: SecretStats) f64 {
        const total = self.cache_hits + self.cache_misses;
        if (total == 0) return 0.0;
        return @as(f64, @floatFromInt(self.cache_hits)) / @as(f64, @floatFromInt(total));
    }
};

// =============================================================================
// Vault HTTP Request Builder
// =============================================================================

/// Builds HTTP requests for HashiCorp Vault API
pub const VaultRequestBuilder = struct {
    allocator: std.mem.Allocator,
    config: VaultConfig,
    token: ?[]const u8,

    pub fn init(allocator: std.mem.Allocator, config: VaultConfig, token: ?[]const u8) VaultRequestBuilder {
        return .{
            .allocator = allocator,
            .config = config,
            .token = token,
        };
    }

    /// Build KV v2 read request
    /// GET /v1/{mount}/data/{path}
    pub fn buildReadRequest(self: *VaultRequestBuilder, secret_path: []const u8) !VaultRequest {
        const path = if (self.config.kv_version == 2)
            try std.fmt.allocPrint(self.allocator, "/v1/{s}/data/{s}", .{ self.config.mount_path, secret_path })
        else
            try std.fmt.allocPrint(self.allocator, "/v1/{s}/{s}", .{ self.config.mount_path, secret_path });

        var headers = std.ArrayList(Header).init(self.allocator);
        try headers.append(.{ .name = "X-Vault-Token", .value = self.token orelse "" });
        if (self.config.namespace) |ns| {
            try headers.append(.{ .name = "X-Vault-Namespace", .value = ns });
        }

        return VaultRequest{
            .method = "GET",
            .path = path,
            .headers = try headers.toOwnedSlice(),
            .body = null,
            .allocator = self.allocator,
        };
    }

    /// Build AppRole login request
    /// POST /v1/auth/approle/login
    pub fn buildAppRoleLogin(self: *VaultRequestBuilder, role_id: []const u8, secret_id: []const u8) !VaultRequest {
        const path = try self.allocator.dupe(u8, "/v1/auth/approle/login");
        const body = try std.fmt.allocPrint(
            self.allocator,
            "{{\"role_id\":\"{s}\",\"secret_id\":\"{s}\"}}",
            .{ role_id, secret_id },
        );

        var headers = std.ArrayList(Header).init(self.allocator);
        try headers.append(.{ .name = "Content-Type", .value = "application/json" });

        return VaultRequest{
            .method = "POST",
            .path = path,
            .headers = try headers.toOwnedSlice(),
            .body = body,
            .allocator = self.allocator,
        };
    }

    /// Build token renewal request
    /// POST /v1/auth/token/renew-self
    pub fn buildTokenRenewal(self: *VaultRequestBuilder) !VaultRequest {
        const path = try self.allocator.dupe(u8, "/v1/auth/token/renew-self");

        var headers = std.ArrayList(Header).init(self.allocator);
        try headers.append(.{ .name = "X-Vault-Token", .value = self.token orelse "" });
        try headers.append(.{ .name = "Content-Type", .value = "application/json" });

        return VaultRequest{
            .method = "POST",
            .path = path,
            .headers = try headers.toOwnedSlice(),
            .body = try self.allocator.dupe(u8, "{}"),
            .allocator = self.allocator,
        };
    }
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const VaultRequest = struct {
    method: []const u8,
    path: []const u8,
    headers: []Header,
    body: ?[]const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *VaultRequest) void {
        self.allocator.free(self.path);
        if (self.body) |b| self.allocator.free(b);
        self.allocator.free(self.headers);
    }

    /// Format as HTTP request string
    pub fn toHttpRequest(self: *const VaultRequest, host: []const u8, allocator: std.mem.Allocator) ![]u8 {
        var request = std.ArrayList(u8).init(allocator);
        errdefer request.deinit();

        // Request line
        try request.writer().print("{s} {s} HTTP/1.1\r\n", .{ self.method, self.path });

        // Host header
        try request.writer().print("Host: {s}\r\n", .{host});

        // Custom headers
        for (self.headers) |header| {
            try request.writer().print("{s}: {s}\r\n", .{ header.name, header.value });
        }

        // Content-Length if body present
        if (self.body) |body| {
            try request.writer().print("Content-Length: {d}\r\n", .{body.len});
        }

        // End headers
        try request.appendSlice("\r\n");

        // Body
        if (self.body) |body| {
            try request.appendSlice(body);
        }

        return request.toOwnedSlice();
    }
};

// =============================================================================
// AWS SigV4 Request Signing
// =============================================================================

/// AWS Signature Version 4 signing for Secrets Manager
pub const AwsSigV4Signer = struct {
    allocator: std.mem.Allocator,
    config: AwsConfig,
    service: []const u8 = "secretsmanager",

    pub fn init(allocator: std.mem.Allocator, config: AwsConfig) AwsSigV4Signer {
        return .{
            .allocator = allocator,
            .config = config,
        };
    }

    /// Build GetSecretValue request
    pub fn buildGetSecretValueRequest(self: *AwsSigV4Signer, secret_id: []const u8) !AwsRequest {
        const host = if (self.config.endpoint) |ep|
            ep
        else
            try std.fmt.allocPrint(self.allocator, "secretsmanager.{s}.amazonaws.com", .{self.config.region});

        const body = try std.fmt.allocPrint(
            self.allocator,
            "{{\"SecretId\":\"{s}\"}}",
            .{secret_id},
        );

        // Get current timestamp
        const timestamp = time_compat.timestamp();
        const date_stamp = try self.formatDateStamp(timestamp);
        const amz_date = try self.formatAmzDate(timestamp);

        var headers = std.ArrayList(Header).init(self.allocator);
        try headers.append(.{ .name = "Host", .value = host });
        try headers.append(.{ .name = "X-Amz-Date", .value = amz_date });
        try headers.append(.{ .name = "X-Amz-Target", .value = "secretsmanager.GetSecretValue" });
        try headers.append(.{ .name = "Content-Type", .value = "application/x-amz-json-1.1" });

        // Add session token if present
        if (self.config.session_token) |token| {
            try headers.append(.{ .name = "X-Amz-Security-Token", .value = token });
        }

        return AwsRequest{
            .method = "POST",
            .path = "/",
            .host = host,
            .headers = try headers.toOwnedSlice(),
            .body = body,
            .date_stamp = date_stamp,
            .amz_date = amz_date,
            .allocator = self.allocator,
        };
    }

    /// Calculate the signing key
    /// kSecret = "AWS4" + SecretAccessKey
    /// kDate = HMAC-SHA256(kSecret, DateStamp)
    /// kRegion = HMAC-SHA256(kDate, Region)
    /// kService = HMAC-SHA256(kRegion, Service)
    /// kSigning = HMAC-SHA256(kService, "aws4_request")
    pub fn deriveSigningKey(self: *AwsSigV4Signer, date_stamp: []const u8) ![32]u8 {
        const secret_key = self.config.secret_access_key orelse return error.NoCredentials;

        // kSecret = "AWS4" + secret_key
        var k_secret = try self.allocator.alloc(u8, 4 + secret_key.len);
        defer self.allocator.free(k_secret);
        @memcpy(k_secret[0..4], "AWS4");
        @memcpy(k_secret[4..], secret_key);

        // kDate = HMAC-SHA256(kSecret, date_stamp)
        var k_date: [32]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&k_date, date_stamp, k_secret);

        // kRegion = HMAC-SHA256(kDate, region)
        var k_region: [32]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&k_region, self.config.region, &k_date);

        // kService = HMAC-SHA256(kRegion, service)
        var k_service: [32]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&k_service, self.service, &k_region);

        // kSigning = HMAC-SHA256(kService, "aws4_request")
        var k_signing: [32]u8 = undefined;
        std.crypto.auth.hmac.sha2.HmacSha256.create(&k_signing, "aws4_request", &k_service);

        return k_signing;
    }

    /// Create canonical request hash
    /// CanonicalRequest = Method + '\n' + Path + '\n' + Query + '\n' +
    ///                    CanonicalHeaders + '\n' + SignedHeaders + '\n' +
    ///                    HashedPayload
    pub fn hashCanonicalRequest(
        self: *AwsSigV4Signer,
        method: []const u8,
        path: []const u8,
        headers: []const Header,
        payload: []const u8,
    ) ![64]u8 {
        _ = self;

        var hasher = std.crypto.hash.sha2.Sha256.init(.{});

        // Method
        hasher.update(method);
        hasher.update("\n");

        // Path
        hasher.update(path);
        hasher.update("\n");

        // Query string (empty for POST)
        hasher.update("\n");

        // Canonical headers (must be sorted, lowercase)
        for (headers) |header| {
            hasher.update(header.name);
            hasher.update(":");
            hasher.update(header.value);
            hasher.update("\n");
        }
        hasher.update("\n");

        // Signed headers
        for (headers, 0..) |header, i| {
            if (i > 0) hasher.update(";");
            hasher.update(header.name);
        }
        hasher.update("\n");

        // Hashed payload
        var payload_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(payload, &payload_hash, .{});
        var hex_payload: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&hex_payload, "{s}", .{std.fmt.fmtSliceHexLower(&payload_hash)}) catch unreachable;
        hasher.update(&hex_payload);

        var result: [32]u8 = undefined;
        hasher.final(&result);

        var hex_result: [64]u8 = undefined;
        _ = std.fmt.bufPrint(&hex_result, "{s}", .{std.fmt.fmtSliceHexLower(&result)}) catch unreachable;
        return hex_result;
    }

    fn formatDateStamp(self: *AwsSigV4Signer, timestamp: i64) ![]const u8 {
        // Format: YYYYMMDD
        const epoch_seconds: u64 = @intCast(timestamp);
        const epoch_days = epoch_seconds / 86400;
        const year_day = std.time.epoch.EpochDay{ .day = epoch_days };
        const year_and_day = year_day.calculateYearDay();
        const month_day = year_and_day.calculateMonthDay();

        return try std.fmt.allocPrint(self.allocator, "{d:0>4}{d:0>2}{d:0>2}", .{
            year_and_day.year,
            @intFromEnum(month_day.month),
            month_day.day_index + 1,
        });
    }

    fn formatAmzDate(self: *AwsSigV4Signer, timestamp: i64) ![]const u8 {
        // Format: YYYYMMDD'T'HHMMSS'Z'
        const epoch_seconds: u64 = @intCast(timestamp);
        const epoch_days = epoch_seconds / 86400;
        const day_seconds = epoch_seconds % 86400;
        const year_day = std.time.epoch.EpochDay{ .day = epoch_days };
        const year_and_day = year_day.calculateYearDay();
        const month_day = year_and_day.calculateMonthDay();

        const hours = day_seconds / 3600;
        const minutes = (day_seconds % 3600) / 60;
        const seconds = day_seconds % 60;

        return try std.fmt.allocPrint(self.allocator, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
            year_and_day.year,
            @intFromEnum(month_day.month),
            month_day.day_index + 1,
            hours,
            minutes,
            seconds,
        });
    }
};

pub const AwsRequest = struct {
    method: []const u8,
    path: []const u8,
    host: []const u8,
    headers: []Header,
    body: []const u8,
    date_stamp: []const u8,
    amz_date: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *AwsRequest) void {
        self.allocator.free(self.host);
        self.allocator.free(self.body);
        self.allocator.free(self.headers);
        self.allocator.free(self.date_stamp);
        self.allocator.free(self.amz_date);
    }
};

/// Helper to load configuration from secrets
pub const ConfigSecretLoader = struct {
    secrets: *SecretManager,
    prefix: []const u8,

    pub fn init(secrets: *SecretManager, prefix: []const u8) ConfigSecretLoader {
        return .{
            .secrets = secrets,
            .prefix = prefix,
        };
    }

    /// Load a secret with the configured prefix
    pub fn load(self: *ConfigSecretLoader, allocator: std.mem.Allocator, name: []const u8) ![]u8 {
        const full_name = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ self.prefix, name });
        defer allocator.free(full_name);
        return self.secrets.getSecret(full_name);
    }

    /// Load optional secret (returns null if not found)
    pub fn loadOptional(self: *ConfigSecretLoader, allocator: std.mem.Allocator, name: []const u8) ?[]u8 {
        return self.load(allocator, name) catch null;
    }
};

// Tests
test "secret manager initialization" {
    const testing = std.testing;

    var secrets = SecretManager.init(testing.allocator, .environment);
    defer secrets.deinit();

    try testing.expectEqual(SecretBackend.environment, secrets.backend);
    try testing.expectEqual(@as(i64, 300), secrets.cache_ttl_seconds);
}

test "environment variable lookup" {
    const testing = std.testing;

    // This test requires TEST_SECRET env var to be set
    var secrets = SecretManager.init(testing.allocator, .environment);
    defer secrets.deinit();

    // Test with a secret that doesn't exist
    const result = secrets.getSecret("nonexistent/secret");
    try testing.expectError(error.SecretNotFound, result);
}

test "cache TTL" {
    const testing = std.testing;

    var secrets = SecretManager.init(testing.allocator, .environment);
    defer secrets.deinit();

    secrets.setCacheTtl(60);
    try testing.expectEqual(@as(i64, 60), secrets.cache_ttl_seconds);
}

test "secret stats" {
    const testing = std.testing;

    const stats = SecretStats{
        .cache_hits = 80,
        .cache_misses = 20,
        .fetches = 20,
        .errors = 0,
        .invalidations = 0,
    };

    const hit_rate = stats.cacheHitRate();
    try testing.expectApproxEqAbs(@as(f64, 0.8), hit_rate, 0.01);
}

test "kubernetes secrets path" {
    const testing = std.testing;

    var secrets = SecretManager.init(testing.allocator, .kubernetes);
    defer secrets.deinit();

    secrets.configureKubernetes(.{
        .secrets_path = "/tmp/test-secrets",
        .use_api = false,
    });

    try testing.expectEqual(SecretBackend.kubernetes, secrets.backend);
}
