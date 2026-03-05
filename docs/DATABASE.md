# Database Schema Documentation

## Overview

The SMTP server uses SQLite as its primary data store for users, messages, queues, and operational data. This document describes the database schema, migrations, and maintenance procedures.

## Database File Location

Default: `./smtp.db`
Configurable via: `SMTP_DB_PATH` environment variable

## Schema Tables

### Users Table

Stores user authentication and account information.

```sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
```

**Columns:**
- `id`: Auto-incrementing primary key
- `username`: Unique username for authentication
- `password_hash`: Argon2id hashed password
- `email`: User's email address
- `enabled`: Boolean (0/1) - account enabled status
- `created_at`: Unix timestamp of creation
- `updated_at`: Unix timestamp of last update

### Messages Queue Table

Stores messages awaiting delivery.

```sql
CREATE TABLE IF NOT EXISTS message_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_address TEXT NOT NULL,
    to_address TEXT NOT NULL,
    message_data BLOB NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 5,
    next_retry_at INTEGER,
    created_at INTEGER NOT NULL,
    last_error TEXT
);

CREATE INDEX idx_queue_next_retry ON message_queue(next_retry_at);
CREATE INDEX idx_queue_priority ON message_queue(priority DESC);
```

**Columns:**
- `id`: Auto-incrementing primary key
- `from_address`: Sender email address
- `to_address`: Recipient email address
- `message_data`: Full message content (BLOB)
- `priority`: Delivery priority (higher = more urgent)
- `retry_count`: Number of delivery attempts
- `max_retries`: Maximum retry attempts before bounce
- `next_retry_at`: Unix timestamp for next delivery attempt
- `created_at`: Unix timestamp of queue entry
- `last_error`: Last delivery error message

### Greylist Table

Implements greylisting anti-spam technique.

```sql
CREATE TABLE IF NOT EXISTS greylist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    passed INTEGER NOT NULL DEFAULT 0,
    UNIQUE(sender, recipient, client_ip)
);

CREATE INDEX idx_greylist_lookup ON greylist(sender, recipient, client_ip);
CREATE INDEX idx_greylist_first_seen ON greylist(first_seen);
```

**Columns:**
- `sender`: Sender email address
- `recipient`: Recipient email address
- `client_ip`: Connecting client IP address
- `first_seen`: First attempt timestamp
- `last_seen`: Most recent attempt timestamp
- `passed`: Boolean - whether greylisting period passed

**Greylisting Logic:**
- First attempt: Record triplet (sender, recipient, IP) and reject with 4xx
- Subsequent attempts before delay: Reject
- After delay period (typically 5 minutes): Accept and mark as passed
- Future attempts: Accept immediately if passed

### Filter Rules Table

Stores spam filter and content filter rules.

```sql
CREATE TABLE IF NOT EXISTS filter_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    rule_type TEXT NOT NULL,
    pattern TEXT NOT NULL,
    action TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

CREATE INDEX idx_filters_enabled ON filter_rules(enabled, priority DESC);
```

**Rule Types:**
- `subject`: Match against email subject
- `from`: Match against sender address
- `to`: Match against recipient address
- `body`: Match against message body
- `header`: Match against specific header

**Actions:**
- `reject`: Reject message with 5xx
- `quarantine`: Move to quarantine folder
- `tag`: Add header tag (e.g., [SPAM])
- `delete`: Silent drop

### Migration History Table

Tracks applied database migrations.

```sql
CREATE TABLE IF NOT EXISTS schema_migrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version INTEGER NOT NULL UNIQUE,
    name TEXT NOT NULL,
    applied_at INTEGER NOT NULL
);
```

## Database Migrations

### Migration Framework

The server uses a custom migration framework (`src/storage/migrations.zig`) that supports:
- Forward migrations (applying changes)
- Rollback migrations (reverting changes)
- Version tracking
- Atomic transactions

### Running Migrations

Migrations run automatically on server startup. To run manually:

```bash
./zig-out/bin/migrate-cli up    # Apply pending migrations
./zig-out/bin/migrate-cli down  # Rollback last migration
./zig-out/bin/migrate-cli list  # List migration status
```

### Creating New Migrations

1. Add migration to `src/storage/migrations.zig`:

```zig
pub const migrations = [_]Migration{
    .{
        .version = 4,
        .name = "add_user_quota",
        .up =
            \\ALTER TABLE users ADD COLUMN quota_mb INTEGER DEFAULT 1024;
        ,
        .down =
            \\ALTER TABLE users DROP COLUMN quota_mb;
        ,
    },
};
```

2. Migrations must include both `up` (apply) and `down` (rollback) SQL
3. Version numbers must be sequential and unique

## Maintenance Procedures

### Backup

**Recommended: Daily backups**

```bash
# SQLite backup (online, safe)
sqlite3 smtp.db ".backup smtp_backup_$(date +%Y%m%d).db"

# Or simple file copy (requires server stop)
systemctl stop mail
cp smtp.db smtp_backup_$(date +%Y%m%d).db
systemctl start mail
```

### Restore

```bash
systemctl stop mail
cp smtp_backup_20231024.db smtp.db
systemctl start mail
```

### Vacuum

Reclaim unused space and optimize database:

```bash
sqlite3 smtp.db "VACUUM;"
```

Recommended: Monthly or after large deletions

### Integrity Check

Verify database integrity:

```bash
sqlite3 smtp.db "PRAGMA integrity_check;"
```

Should return: `ok`

### Index Optimization

Rebuild indices for optimal performance:

```bash
sqlite3 smtp.db "REINDEX;"
```

### Queue Cleanup

Remove old processed messages:

```sql
DELETE FROM message_queue
WHERE created_at < strftime('%s', 'now', '-30 days')
AND next_retry_at IS NULL;
```

### Greylist Cleanup

Remove old greylist entries:

```sql
DELETE FROM greylist
WHERE last_seen < strftime('%s', 'now', '-30 days');
```

## Performance Tuning

### WAL Mode

Write-Ahead Logging for better concurrency:

```sql
PRAGMA journal_mode=WAL;
```

Already enabled by default in the server.

### Connection Pooling

The server maintains a connection pool (default: 10 connections).
Configure via: `SMTP_DB_POOL_SIZE`

### Indices

Critical indices are created automatically. Monitor query performance:

```sql
EXPLAIN QUERY PLAN SELECT * FROM message_queue WHERE next_retry_at < ?;
```

### Statistics

Update query optimizer statistics:

```sql
ANALYZE;
```

## Monitoring

### Database Size

```bash
ls -lh smtp.db
```

Typical sizes:
- Small deployment: < 100MB
- Medium deployment: 100MB - 1GB
- Large deployment: > 1GB

### Queue Depth

```sql
SELECT COUNT(*) FROM message_queue WHERE next_retry_at IS NOT NULL;
```

Alert if > 10,000 for extended period.

### Greylist Entries

```sql
SELECT COUNT(*) FROM greylist;
```

Typical: 10,000 - 100,000 entries

### Failed Deliveries

```sql
SELECT COUNT(*) FROM message_queue WHERE retry_count >= max_retries;
```

These should be investigated and eventually purged.

## Troubleshooting

### Database Locked

**Symptom:** `database is locked` errors

**Causes:**
- Long-running transaction
- Concurrent write from backup
- File system issue

**Solutions:**
1. Check for stuck transactions
2. Ensure backups use `.backup` command (not file copy)
3. Verify WAL mode is enabled
4. Increase busy timeout: `PRAGMA busy_timeout=5000;`

### Corruption

**Symptom:** `database disk image is malformed`

**Recovery:**
1. Stop server immediately
2. Run integrity check: `sqlite3 smtp.db "PRAGMA integrity_check;"`
3. If corrupt, restore from last known good backup
4. If no backup, attempt dump and reimport:

```bash
sqlite3 smtp.db ".dump" > dump.sql
mv smtp.db smtp.db.corrupt
sqlite3 smtp_new.db < dump.sql
```

### Slow Queries

**Symptom:** High latency on database operations

**Solutions:**
1. Run `VACUUM` to defragment
2. Run `ANALYZE` to update statistics
3. Check for missing indices
4. Review and optimize slow queries
5. Consider archiving old data

### Disk Full

**Symptom:** `disk I/O error` or write failures

**Solutions:**
1. Free up disk space
2. Archive/delete old messages
3. Run `VACUUM` to reclaim space
4. Move database to larger partition

## Security

### File Permissions

```bash
chmod 600 smtp.db
chown smtp:smtp smtp.db
```

### Encryption at Rest

For sensitive deployments, use filesystem-level encryption (LUKS, dm-crypt) or encrypted partition.

SQLite does not natively support encryption. Consider SQLCipher for database-level encryption.

### Backup Security

Encrypt backups if stored off-site:

```bash
sqlite3 smtp.db ".backup smtp_backup.db"
openssl enc -aes-256-cbc -salt -in smtp_backup.db -out smtp_backup.db.enc
rm smtp_backup.db
```

## Schema Evolution

### Adding Columns

Safe - can be done online:

```sql
ALTER TABLE users ADD COLUMN phone TEXT;
```

### Removing Columns

Requires table recreation (not supported in SQLite ALTER TABLE):

```sql
BEGIN TRANSACTION;
CREATE TABLE users_new AS SELECT id, username, email FROM users;
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;
COMMIT;
```

### Changing Column Types

Requires table recreation with data migration.

Always use migrations framework for schema changes!

## Multi-Tenancy Considerations

For multi-tenant deployments, see `docs/MULTI_TENANCY.md`:
- Tenant isolation with `tenant_id` columns
- Row-level security
- Per-tenant quotas and limits
- Tenant-specific backup/restore

## References

- SQLite Documentation: https://www.sqlite.org/docs.html
- WAL Mode: https://www.sqlite.org/wal.html
- SQLite Best Practices: https://www.sqlite.org/bestpractice.html
- Migration Framework: `src/storage/migrations.zig`
