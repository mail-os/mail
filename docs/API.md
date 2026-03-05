# Mail Server API Documentation

Complete API reference for the SMTP server including REST API, CLI tools, and programmatic interfaces.

## Table of Contents

- [REST API](#rest-api)
- [CLI Tools](#cli-tools)
- [Protocol Extensions](#protocol-extensions)
- [Configuration API](#configuration-api)
- [Storage API](#storage-api)
- [Authentication API](#authentication-api)
- [Monitoring API](#monitoring-api)

---

## REST API

The SMTP server exposes a REST API for administration and monitoring on port 8080 (configurable).

### Base URL

```
http://localhost:8080
```

### Authentication

All API endpoints require HTTP Basic Authentication (except health check).

```
Authorization: Basic base64(username:password)
```

### Health Check

**Endpoint:** `GET /health`

**Description:** Check server health and readiness.

**Authentication:** None required

**Response:**
```json
{
  "status": "healthy",
  "version": "0.14.0",
  "uptime_seconds": 3600,
  "connections": {
    "active": 5,
    "total": 1234
  },
  "memory": {
    "allocated_mb": 45.2,
    "heap_mb": 38.1
  }
}
```

**Status Codes:**
- `200 OK` - Server is healthy
- `503 Service Unavailable` - Server is unhealthy

**Example:**
```bash
curl http://localhost:8080/health
```

---

### Statistics

**Endpoint:** `GET /stats`

**Description:** Get detailed server statistics.

**Authentication:** Required

**Response:**
```json
{
  "messages": {
    "received": 1234,
    "sent": 1200,
    "queued": 10,
    "failed": 24
  },
  "connections": {
    "current": 5,
    "total": 5678,
    "rejected": 123
  },
  "authentication": {
    "attempts": 234,
    "successful": 200,
    "failed": 34
  },
  "spam": {
    "detected": 45,
    "rate": 0.036
  },
  "virus": {
    "detected": 2,
    "rate": 0.0016
  },
  "storage": {
    "messages_stored": 1200,
    "total_size_mb": 456.7
  },
  "performance": {
    "avg_processing_ms": 12.3,
    "p95_processing_ms": 45.6,
    "p99_processing_ms": 89.1
  }
}
```

**Status Codes:**
- `200 OK` - Statistics retrieved
- `401 Unauthorized` - Authentication required
- `500 Internal Server Error` - Error retrieving stats

**Example:**
```bash
curl -u admin:password http://localhost:8080/stats
```

---

### Prometheus Metrics

**Endpoint:** `GET /metrics`

**Description:** Prometheus-compatible metrics endpoint.

**Authentication:** None required (localhost only by default)

**Response Format:** Prometheus text format

**Metrics Exposed:**
- `smtp_messages_received_total` - Total messages received
- `smtp_messages_sent_total` - Total messages sent
- `smtp_messages_queued` - Current queue size
- `smtp_connections_active` - Active connections
- `smtp_connections_total` - Total connections
- `smtp_auth_attempts_total` - Authentication attempts
- `smtp_spam_detected_total` - Spam messages detected
- `smtp_virus_detected_total` - Viruses detected
- `smtp_processing_duration_seconds` - Processing time histogram

**Example:**
```bash
curl http://localhost:8081/metrics
```

---

### User Management

#### List Users

**Endpoint:** `GET /api/users`

**Description:** List all users in the system.

**Authentication:** Required (admin)

**Query Parameters:**
- `offset` (optional) - Pagination offset (default: 0)
- `limit` (optional) - Number of users to return (default: 100, max: 1000)

**Response:**
```json
{
  "users": [
    {
      "id": 1,
      "username": "john",
      "email": "john@example.com",
      "created_at": "2025-10-20T10:30:00Z",
      "last_login": "2025-10-23T08:15:00Z",
      "quota_mb": 1000,
      "used_mb": 234.5,
      "enabled": true
    }
  ],
  "total": 42,
  "offset": 0,
  "limit": 100
}
```

**Status Codes:**
- `200 OK` - Users retrieved
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Not an admin user

**Example:**
```bash
curl -u admin:password http://localhost:8080/api/users?limit=50
```

---

#### Get User

**Endpoint:** `GET /api/users/{username}`

**Description:** Get details for a specific user.

**Authentication:** Required

**Response:**
```json
{
  "id": 1,
  "username": "john",
  "email": "john@example.com",
  "created_at": "2025-10-20T10:30:00Z",
  "last_login": "2025-10-23T08:15:00Z",
  "quota_mb": 1000,
  "used_mb": 234.5,
  "enabled": true,
  "statistics": {
    "messages_received": 456,
    "messages_sent": 789,
    "storage_used_mb": 234.5
  }
}
```

**Status Codes:**
- `200 OK` - User found
- `401 Unauthorized` - Authentication required
- `404 Not Found` - User not found

**Example:**
```bash
curl -u admin:password http://localhost:8080/api/users/john
```

---

#### Create User

**Endpoint:** `POST /api/users`

**Description:** Create a new user.

**Authentication:** Required (admin)

**Request Body:**
```json
{
  "username": "jane",
  "email": "jane@example.com",
  "password": "SecureP@ssw0rd",
  "quota_mb": 1000
}
```

**Response:**
```json
{
  "id": 2,
  "username": "jane",
  "email": "jane@example.com",
  "created_at": "2025-10-23T12:00:00Z",
  "quota_mb": 1000,
  "enabled": true
}
```

**Status Codes:**
- `201 Created` - User created
- `400 Bad Request` - Invalid request (validation error)
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Not an admin user
- `409 Conflict` - User already exists

**Example:**
```bash
curl -u admin:password -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{"username":"jane","email":"jane@example.com","password":"SecureP@ssw0rd","quota_mb":1000}'
```

---

#### Update User

**Endpoint:** `PUT /api/users/{username}`

**Description:** Update user settings.

**Authentication:** Required (admin or self)

**Request Body:**
```json
{
  "email": "newemail@example.com",
  "quota_mb": 2000,
  "enabled": true
}
```

**Response:**
```json
{
  "id": 1,
  "username": "john",
  "email": "newemail@example.com",
  "quota_mb": 2000,
  "enabled": true
}
```

**Status Codes:**
- `200 OK` - User updated
- `400 Bad Request` - Invalid request
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Cannot update other users
- `404 Not Found` - User not found

**Example:**
```bash
curl -u admin:password -X PUT http://localhost:8080/api/users/john \
  -H "Content-Type: application/json" \
  -d '{"quota_mb":2000}'
```

---

#### Delete User

**Endpoint:** `DELETE /api/users/{username}`

**Description:** Delete a user and all their data.

**Authentication:** Required (admin)

**Response:**
```json
{
  "success": true,
  "message": "User deleted successfully"
}
```

**Status Codes:**
- `200 OK` - User deleted
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Not an admin user
- `404 Not Found` - User not found

**Example:**
```bash
curl -u admin:password -X DELETE http://localhost:8080/api/users/john
```

---

### Queue Management

#### List Queued Messages

**Endpoint:** `GET /api/queue`

**Description:** List messages in the delivery queue.

**Authentication:** Required (admin)

**Query Parameters:**
- `offset` (optional) - Pagination offset
- `limit` (optional) - Number of messages (default: 100)
- `status` (optional) - Filter by status (pending, retry, failed)

**Response:**
```json
{
  "messages": [
    {
      "id": "msg_abc123",
      "from": "sender@example.com",
      "to": ["recipient@example.com"],
      "subject": "Test Email",
      "size_bytes": 1234,
      "attempts": 1,
      "max_attempts": 5,
      "next_retry": "2025-10-23T13:00:00Z",
      "status": "retry",
      "created_at": "2025-10-23T12:00:00Z"
    }
  ],
  "total": 10,
  "offset": 0,
  "limit": 100
}
```

**Status Codes:**
- `200 OK` - Queue retrieved
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Not an admin user

**Example:**
```bash
curl -u admin:password http://localhost:8080/api/queue?status=retry
```

---

#### Retry Message

**Endpoint:** `POST /api/queue/{message_id}/retry`

**Description:** Force immediate retry of a queued message.

**Authentication:** Required (admin)

**Response:**
```json
{
  "success": true,
  "message": "Message queued for immediate retry"
}
```

**Status Codes:**
- `200 OK` - Message queued for retry
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Not an admin user
- `404 Not Found` - Message not found

**Example:**
```bash
curl -u admin:password -X POST http://localhost:8080/api/queue/msg_abc123/retry
```

---

#### Delete Queued Message

**Endpoint:** `DELETE /api/queue/{message_id}`

**Description:** Remove a message from the queue.

**Authentication:** Required (admin)

**Response:**
```json
{
  "success": true,
  "message": "Message removed from queue"
}
```

**Status Codes:**
- `200 OK` - Message removed
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Not an admin user
- `404 Not Found` - Message not found

**Example:**
```bash
curl -u admin:password -X DELETE http://localhost:8080/api/queue/msg_abc123
```

---

## CLI Tools

### user-cli

Command-line tool for user management.

#### Create User

```bash
user-cli create <username> <email> <password>
```

**Example:**
```bash
user-cli create john john@example.com MyP@ssw0rd
```

**Output:**
```
User created successfully:
  Username: john
  Email: john@example.com
  ID: 1
```

---

#### List Users

```bash
user-cli list [--limit N]
```

**Example:**
```bash
user-cli list --limit 50
```

**Output:**
```
Users:
  1. john (john@example.com) - Created: 2025-10-20
  2. jane (jane@example.com) - Created: 2025-10-21
Total: 2
```

---

#### Update Password

```bash
user-cli update-password <username> <new_password>
```

**Example:**
```bash
user-cli update-password john NewP@ssw0rd123
```

**Output:**
```
Password updated successfully for user: john
```

---

#### Set Quota

```bash
user-cli set-quota <username> <quota_mb>
```

**Example:**
```bash
user-cli set-quota john 2000
```

**Output:**
```
Quota set to 2000 MB for user: john
```

---

#### Delete User

```bash
user-cli delete <username>
```

**Example:**
```bash
user-cli delete john
```

**Output:**
```
User deleted successfully: john
```

---

#### Verify User

```bash
user-cli verify <username> <password>
```

**Example:**
```bash
user-cli verify john MyP@ssw0rd
```

**Output:**
```
Authentication successful for user: john
```

---

#### Show User Info

```bash
user-cli info <username>
```

**Example:**
```bash
user-cli info john
```

**Output:**
```
User Information:
  Username: john
  Email: john@example.com
  ID: 1
  Created: 2025-10-20 10:30:00
  Last Login: 2025-10-23 08:15:00
  Quota: 1000 MB
  Used: 234.5 MB (23.5%)
  Status: Enabled
```

---

## Protocol Extensions

### SMTP Extensions Supported

The server advertises these extensions in EHLO response:

#### PIPELINING (RFC 2920)

Allows clients to send multiple commands without waiting for responses.

**Example:**
```
C: MAIL FROM:<sender@example.com>
C: RCPT TO:<recipient@example.com>
C: DATA
S: 250 OK
S: 250 OK
S: 354 Start mail input
```

---

#### SIZE (RFC 1870)

Advertises maximum message size and allows size declaration.

**EHLO Response:**
```
250-SIZE 52428800
```

**Usage:**
```
MAIL FROM:<sender@example.com> SIZE=1234567
```

**Responses:**
- `250 OK` - Size acceptable
- `552 Message exceeds maximum size` - Too large

---

#### SMTPUTF8 (RFC 6531)

Supports international email addresses with UTF-8 encoding.

**EHLO Response:**
```
250-SMTPUTF8
```

**Usage:**
```
MAIL FROM:<用户@例え.jp> SMTPUTF8
```

---

#### STARTTLS (RFC 3207)

Upgrades connection to TLS.

**EHLO Response:**
```
250-STARTTLS
```

**Usage:**
```
C: STARTTLS
S: 220 Ready to start TLS
[TLS handshake]
```

---

#### AUTH (RFC 4954)

Supports SMTP authentication.

**EHLO Response:**
```
250-AUTH PLAIN LOGIN
```

**Mechanisms:**
- `PLAIN` - Base64-encoded username/password
- `LOGIN` - Legacy base64 authentication

**Example (PLAIN):**
```
C: AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk
S: 235 Authentication successful
```

---

#### CHUNKING (RFC 3030)

Binary message transmission via BDAT command.

**EHLO Response:**
```
250-CHUNKING
```

**Usage:**
```
C: BDAT 1000
C: [1000 bytes of data]
S: 250 Chunk received
C: BDAT 500 LAST
C: [500 bytes of data]
S: 250 Message accepted
```

---

#### DELIVERBY (RFC 2852)

Time-constrained delivery.

**EHLO Response:**
```
250-DELIVERBY 86400
```

**Usage:**
```
MAIL FROM:<sender@example.com> BY=3600;R
```

**Parameters:**
- Time in seconds
- `R` - Return notification if can't deliver in time
- `N` - No notification

---

#### ETRN (RFC 1985)

Remote queue processing trigger.

**EHLO Response:**
```
250-ETRN
```

**Usage:**
```
C: ETRN example.com
S: 250 Queuing started for example.com
```

---

#### ATRN (RFC 2645)

Authenticated TURN for dial-up connections.

**EHLO Response:**
```
250-ATRN
```

**Usage:**
```
C: AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk
S: 235 Authentication successful
C: ATRN example.com
S: 250 Now accepting mail for example.com
```

---

## Configuration API

### Environment Variables

Configure the server via environment variables:

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SMTP_PORT` | int | 2525 | SMTP server port |
| `SMTP_HOST` | string | 0.0.0.0 | Bind address |
| `SMTP_MAX_CONNECTIONS` | int | 100 | Max concurrent connections |
| `SMTP_MAX_MESSAGE_SIZE` | int | 52428800 | Max message size (50MB) |
| `SMTP_TIMEOUT_SECONDS` | int | 300 | Connection timeout |
| `SMTP_HOSTNAME` | string | localhost | Server hostname |
| `SMTP_DB_PATH` | string | smtp.db | SQLite database path |
| `SMTP_STORAGE_TYPE` | string | maildir | Storage backend (maildir/mbox/database/s3/timeseries) |
| `SMTP_STORAGE_PATH` | string | /var/mail | Storage directory |
| `SMTP_ENABLE_TLS` | bool | false | Enable STARTTLS |
| `SMTP_TLS_CERT` | string | - | TLS certificate path |
| `SMTP_TLS_KEY` | string | - | TLS private key path |
| `SMTP_ENABLE_AUTH` | bool | true | Require authentication |
| `SMTP_HEALTH_PORT` | int | 8080 | Health/API port |
| `SMTP_METRICS_PORT` | int | 8081 | Prometheus metrics port |
| `SMTP_LOG_LEVEL` | string | info | Log level (debug/info/warn/error) |
| `SMTP_ENABLE_SPAMASSASSIN` | bool | false | Enable SpamAssassin |
| `SMTP_SPAMASSASSIN_HOST` | string | 127.0.0.1 | SpamAssassin host |
| `SMTP_SPAMASSASSIN_PORT` | int | 783 | SpamAssassin port |
| `SMTP_ENABLE_CLAMAV` | bool | false | Enable ClamAV |
| `SMTP_CLAMAV_HOST` | string | 127.0.0.1 | ClamAV host |
| `SMTP_CLAMAV_PORT` | int | 3310 | ClamAV port |

**Example:**
```bash
export SMTP_PORT=25
export SMTP_MAX_CONNECTIONS=200
export SMTP_ENABLE_TLS=true
export SMTP_TLS_CERT=/etc/smtp/cert.pem
export SMTP_TLS_KEY=/etc/smtp/key.pem
./mail
```

---

## Storage API

### Maildir Storage

Traditional maildir format with cur/new/tmp directories.

**Directory Structure:**
```
/var/mail/user@example.com/
├── cur/
│   └── 1234567890.M123P456.hostname:2,S
├── new/
│   └── 1234567891.M124P457.hostname
└── tmp/
```

**File Naming:** `<timestamp>.M<microseconds>P<pid>.<hostname>:2,<flags>`

**Flags:**
- `S` - Seen
- `R` - Replied
- `F` - Flagged
- `T` - Trashed
- `D` - Draft

---

### mbox Storage

Traditional Unix mbox format with "From " separators.

**File Structure:**
```
From sender@example.com Mon Oct 23 12:00:00 2025
From: sender@example.com
To: recipient@example.com
Subject: Test

Message body

From sender2@example.com Mon Oct 23 13:00:00 2025
...
```

**From Line Escaping:** Lines starting with "From " in message body are escaped with ">"

---

### Database Storage

SQLite/PostgreSQL storage for queryability.

**Schema:**
```sql
CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    message_id TEXT UNIQUE,
    user TEXT,
    folder TEXT,
    from_addr TEXT,
    to_addrs TEXT,
    subject TEXT,
    date TIMESTAMP,
    size INTEGER,
    flags TEXT,
    body BLOB,
    headers TEXT
);

CREATE INDEX idx_messages_user ON messages(user);
CREATE INDEX idx_messages_folder ON messages(user, folder);
CREATE INDEX idx_messages_date ON messages(date);
CREATE VIRTUAL TABLE messages_fts USING fts5(subject, body);
```

---

### Time-Series Storage

Date-based filesystem hierarchy for easy archival.

**Directory Structure:**
```
/var/mail/
├── 2025/
│   ├── 10/
│   │   ├── 20/
│   │   │   ├── msg_abc123.eml
│   │   │   └── msg_def456.eml
│   │   ├── 21/
│   │   └── 22/
│   └── 11/
└── 2024/
```

**Encryption:** Compatible with encrypted storage wrapper (AES-256-GCM)

---

### S3 Storage

Object storage for cloud-scale deployments.

**Key Format:** `{bucket}/{year}/{month}/{day}/{message-id}.eml`

**Configuration:**
```bash
export SMTP_S3_BUCKET=my-mail-bucket
export SMTP_S3_REGION=us-east-1
export SMTP_S3_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
export SMTP_S3_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

---

## Authentication API

### Argon2id Password Hashing

All passwords are hashed using Argon2id with secure parameters.

**Parameters:**
- Time cost: 3 iterations
- Memory cost: 65536 KB (64 MB)
- Parallelism: 4 threads
- Salt: 16 bytes (random)
- Output: 32 bytes

**Hash Format:**
```
$argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
```

---

### SMTP AUTH Mechanisms

#### PLAIN

Base64-encoded: `\0username\0password`

```
C: AUTH PLAIN
S: 334
C: AHVzZXJuYW1lAHBhc3N3b3Jk
S: 235 Authentication successful
```

#### LOGIN (Legacy)

```
C: AUTH LOGIN
S: 334 VXNlcm5hbWU6
C: dXNlcm5hbWU=
S: 334 UGFzc3dvcmQ6
C: cGFzc3dvcmQ=
S: 235 Authentication successful
```

---

## Monitoring API

### Health Check Details

The `/health` endpoint provides:
- Server status (healthy/unhealthy)
- Version information
- Uptime in seconds
- Active/total connections
- Memory usage statistics

**Unhealthy Conditions:**
- Database connection lost
- Disk space < 10%
- Memory usage > 90%
- Too many failed connection attempts

---

### Metrics Details

Prometheus metrics include:

**Counters:**
- `smtp_messages_received_total{status}` - Messages received (accepted/rejected)
- `smtp_messages_sent_total{status}` - Messages sent (delivered/failed)
- `smtp_auth_attempts_total{result}` - Auth attempts (success/failure)
- `smtp_spam_detected_total` - Spam messages
- `smtp_virus_detected_total` - Virus detections

**Gauges:**
- `smtp_connections_active` - Current active connections
- `smtp_messages_queued` - Current queue size
- `smtp_memory_bytes` - Memory usage

**Histograms:**
- `smtp_processing_duration_seconds` - Message processing time
- `smtp_message_size_bytes` - Message sizes

---

## Error Codes

### HTTP Status Codes

| Code | Meaning | When Used |
|------|---------|-----------|
| 200 | OK | Request successful |
| 201 | Created | Resource created |
| 400 | Bad Request | Invalid input |
| 401 | Unauthorized | Authentication required |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 500 | Internal Server Error | Server error |
| 503 | Service Unavailable | Server unhealthy |

### SMTP Response Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 220 | Service ready | Greeting message |
| 221 | Closing connection | QUIT response |
| 235 | Authentication successful | AUTH success |
| 250 | OK | Command successful |
| 251 | User not local | Will forward |
| 252 | Cannot verify | VRFY response |
| 354 | Start mail input | DATA response |
| 421 | Service not available | Temporary error |
| 450 | Mailbox unavailable | Try again later |
| 451 | Local error | Processing error |
| 452 | Insufficient storage | Disk full |
| 500 | Syntax error | Command not recognized |
| 501 | Syntax error in parameters | Invalid arguments |
| 502 | Command not implemented | Not supported |
| 503 | Bad sequence | Out of order |
| 504 | Parameter not implemented | Not supported |
| 521 | Domain does not accept mail | Rejected |
| 530 | Authentication required | Must AUTH |
| 535 | Authentication failed | Bad credentials |
| 550 | Mailbox unavailable | Permanent error |
| 551 | User not local | Rejected |
| 552 | Exceeded storage | Message too large |
| 553 | Mailbox name invalid | Bad address |
| 554 | Transaction failed | Permanent error |

---

## Rate Limiting

### Per-IP Rate Limits

Default limits per IP address:

- **Connection rate**: 10 connections/minute
- **Command rate**: 100 commands/minute
- **Auth attempts**: 5 failures/hour
- **Message rate**: 20 messages/hour

**Headers (REST API):**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 87
X-RateLimit-Reset: 1634567890
```

**Response (rate limited):**
```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
```

---

## WebHooks

### Event Notifications

Configure webhooks for real-time notifications:

**Configuration:**
```bash
export SMTP_WEBHOOK_URL=https://example.com/webhook
export SMTP_WEBHOOK_EVENTS=message.received,spam.detected
```

**Events:**
- `message.received` - New message received
- `message.sent` - Message delivered
- `message.failed` - Delivery failed
- `spam.detected` - Spam detected
- `virus.detected` - Virus detected
- `user.created` - User created
- `auth.failed` - Authentication failed

**Payload Example:**
```json
{
  "event": "message.received",
  "timestamp": "2025-10-23T12:00:00Z",
  "data": {
    "message_id": "msg_abc123",
    "from": "sender@example.com",
    "to": ["recipient@example.com"],
    "subject": "Test Email",
    "size_bytes": 1234
  }
}
```

---

## Versioning

API Version: `v1`

The API follows semantic versioning. Breaking changes will increment the major version.

**Version Header:**
```
X-API-Version: 1.0
```

---

## License

MIT License - See LICENSE file for details.
