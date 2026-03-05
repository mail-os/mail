-- Multi-tenancy database schema
-- This schema supports isolated tenant operations with resource limits

-- Tenants table
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,

    -- Resource limits
    max_users INTEGER NOT NULL DEFAULT 0,
    max_domains INTEGER NOT NULL DEFAULT 0,
    max_storage_mb INTEGER NOT NULL DEFAULT 0,
    max_messages_per_day INTEGER NOT NULL DEFAULT 0,

    -- Features (stored as JSON for flexibility)
    features TEXT NOT NULL DEFAULT '{}',

    -- Tier information
    tier TEXT NOT NULL DEFAULT 'free',

    -- Metadata (JSON)
    metadata TEXT
);

-- Tenant domains (for custom domains feature)
CREATE TABLE IF NOT EXISTS tenant_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    domain TEXT NOT NULL UNIQUE,
    verified INTEGER NOT NULL DEFAULT 0,
    verified_at INTEGER,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Tenant usage tracking
CREATE TABLE IF NOT EXISTS tenant_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    date TEXT NOT NULL, -- YYYY-MM-DD format
    messages_sent INTEGER NOT NULL DEFAULT 0,
    messages_received INTEGER NOT NULL DEFAULT 0,
    storage_used_mb INTEGER NOT NULL DEFAULT 0,
    users_count INTEGER NOT NULL DEFAULT 0,
    domains_count INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    UNIQUE(tenant_id, date)
);

-- Update existing users table to add tenant_id
-- ALTER TABLE users ADD COLUMN tenant_id TEXT REFERENCES tenants(id) ON DELETE CASCADE;

-- Create new users table with tenant support
CREATE TABLE IF NOT EXISTS users_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_login INTEGER,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    UNIQUE(tenant_id, username),
    UNIQUE(tenant_id, email)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_tenants_domain ON tenants(domain);
CREATE INDEX IF NOT EXISTS idx_tenants_enabled ON tenants(enabled);
CREATE INDEX IF NOT EXISTS idx_tenant_domains_tenant ON tenant_domains(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_domains_domain ON tenant_domains(domain);
CREATE INDEX IF NOT EXISTS idx_tenant_usage_tenant_date ON tenant_usage(tenant_id, date);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users_new(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users_new(email);

-- Migration script to move existing users to tenant system
-- This should be run manually after creating a default tenant
-- INSERT INTO tenants (id, name, domain, enabled, created_at, updated_at, tier)
-- VALUES ('default', 'Default Tenant', 'localhost', 1, strftime('%s', 'now'), strftime('%s', 'now'), 'enterprise');
--
-- INSERT INTO users_new (tenant_id, username, password_hash, email, role, enabled, created_at, updated_at)
-- SELECT 'default', username, password_hash, email, role, enabled, created_at, updated_at
-- FROM users;
--
-- DROP TABLE users;
-- ALTER TABLE users_new RENAME TO users;

-- Sample data for testing
-- INSERT INTO tenants (id, name, domain, enabled, created_at, updated_at, max_users, max_domains, max_storage_mb, max_messages_per_day, tier, features)
-- VALUES
--     ('tenant_test1', 'Test Company', 'test.example.com', 1, strftime('%s', 'now'), strftime('%s', 'now'), 25, 3, 10240, 1000, 'starter',
--      '{"spam_filtering":true,"virus_scanning":true,"dkim_signing":true,"mailing_lists":false,"webhooks":false,"api_access":true,"custom_domains":false,"priority_support":false}'),
--     ('tenant_test2', 'Pro Company', 'pro.example.com', 1, strftime('%s', 'now'), strftime('%s', 'now'), 100, 10, 102400, 10000, 'professional',
--      '{"spam_filtering":true,"virus_scanning":true,"dkim_signing":true,"mailing_lists":true,"webhooks":true,"api_access":true,"custom_domains":true,"priority_support":false}');
