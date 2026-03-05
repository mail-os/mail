# Mail Server API Reference

**Version:** v0.28.0
**Date:** 2025-10-24

## Overview

The SMTP server provides two HTTP APIs:

1. **Health & Metrics API** (port 8081) - Monitoring and observability
2. **Management API** (port 8080) - Administrative operations

All APIs return JSON responses unless otherwise specified.

---

## Health & Metrics API

Default port: `8081` (localhost only)

### GET /health

Health check endpoint with dependency monitoring.

**Response:** `200 OK` (healthy), `200 OK` (degraded), or `503 Service Unavailable` (unhealthy)

**Response Body:**
```json
{
  "status": "healthy",
  "uptime_seconds": 3600,
  "active_connections": 15,
  "max_connections": 100,
  "memory_usage_mb": 45.2,
  "checks": {
    "smtp_server": true,
    "connections_available": true,
    "database": true,
    "filesystem": true
  },
  "dependencies": [
    {
      "name": "database",
      "healthy": true,
      "response_time_ms": 2.5
    },
    {
      "name": "filesystem",
      "healthy": true,
      "response_time_ms": 0.8
    }
  ]
}
```

**Fields:**
- `status`: Overall health status (`healthy`, `degraded`, `unhealthy`)
- `uptime_seconds`: Server uptime in seconds
- `active_connections`: Currently active SMTP connections
- `max_connections`: Maximum allowed connections
- `memory_usage_mb`: Memory usage in MB (Linux only)
- `checks`: Boolean checks for various components
- `dependencies`: Array of dependency health status with response times

**Health Status Logic:**
- `healthy`: All systems operational, < 90% connection capacity
- `degraded`: Non-critical failures or 90-100% connection capacity
- `unhealthy`: Critical failures (database unavailable, disk full)

**Example:**
```bash
curl http://localhost:8081/health
```

---

### GET /stats

Server statistics with performance metrics.

**Response:** `200 OK`

**Response Body:**
```json
{
  "uptime_seconds": 3600,
  "total_connections": 1523,
  "active_connections": 15,
  "messages_received": 450,
  "messages_rejected": 23,
  "auth_successes": 427,
  "auth_failures": 12,
  "rate_limit_hits": 8,
  "dnsbl_blocks": 15,
  "greylist_blocks": 5
}
```

**Fields:**
- `uptime_seconds`: Server uptime since start
- `total_connections`: Cumulative connection count
- `active_connections`: Current active connections
- `messages_received`: Total messages accepted
- `messages_rejected`: Total messages rejected
- `auth_successes`: Successful authentications
- `auth_failures`: Failed authentications
- `rate_limit_hits`: Rate limit violations
- `dnsbl_blocks`: Blocked by DNSBL/RBL
- `greylist_blocks`: Temporarily blocked by greylisting

**Example:**
```bash
curl http://localhost:8081/stats
```

---

### GET /metrics

Prometheus-compatible metrics endpoint.

**Response:** `200 OK`
**Content-Type:** `text/plain; version=0.0.4`

**Response Body:**
```
# HELP smtp_uptime_seconds Server uptime in seconds
# TYPE smtp_uptime_seconds gauge
smtp_uptime_seconds 3600
# HELP smtp_connections_total Total number of connections
# TYPE smtp_connections_total counter
smtp_connections_total 1523
# HELP smtp_connections_active Currently active connections
# TYPE smtp_connections_active gauge
smtp_connections_active 15
# HELP smtp_messages_received_total Total messages received
# TYPE smtp_messages_received_total counter
smtp_messages_received_total 450
# HELP smtp_messages_rejected_total Total messages rejected
# TYPE smtp_messages_rejected_total counter
smtp_messages_rejected_total 23
# HELP smtp_auth_successes_total Total successful authentications
# TYPE smtp_auth_successes_total counter
smtp_auth_successes_total 427
# HELP smtp_auth_failures_total Total failed authentications
# TYPE smtp_auth_failures_total counter
smtp_auth_failures_total 12
# HELP smtp_rate_limit_hits_total Total rate limit hits
# TYPE smtp_rate_limit_hits_total counter
smtp_rate_limit_hits_total 8
# HELP smtp_dnsbl_blocks_total Total DNSBL blocks
# TYPE smtp_dnsbl_blocks_total counter
smtp_dnsbl_blocks_total 15
# HELP smtp_greylist_blocks_total Total greylist blocks
# TYPE smtp_greylist_blocks_total counter
smtp_greylist_blocks_total 5
```

**Prometheus Configuration:**
```yaml
scrape_configs:
  - job_name: 'mail'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:8081']
```

**Example:**
```bash
curl http://localhost:8081/metrics
```

---

## Management API

Default port: `8080` (localhost only)

### CSRF Protection

All state-changing operations (POST, PUT, DELETE) require a CSRF token.

**Workflow:**
1. GET `/api/csrf-token` to obtain token
2. Include token in `X-CSRF-Token` header for mutations

---

### GET /api/csrf-token

Generate a new CSRF token for subsequent API calls.

**Response:** `200 OK`

**Response Body:**
```json
{
  "token": "a1b2c3d4e5f6g7h8i9j0"
}
```

**Example:**
```bash
TOKEN=$(curl -s http://localhost:8080/api/csrf-token | jq -r '.token')
```

---

### User Management

#### GET /api/users

List all users.

**Response:** `200 OK`

**Response Body:**
```json
{
  "users": [
    {
      "id": 1,
      "username": "john@example.com",
      "email": "john@example.com",
      "enabled": true,
      "created_at": 1698765432,
      "updated_at": 1698765432
    }
  ],
  "total": 1
}
```

**Example:**
```bash
curl http://localhost:8080/api/users
```

---

#### GET /api/users/{id}

Get user by ID.

**Path Parameters:**
- `id`: User ID (integer)

**Response:** `200 OK` or `404 Not Found`

**Response Body:**
```json
{
  "id": 1,
  "username": "john@example.com",
  "email": "john@example.com",
  "enabled": true,
  "created_at": 1698765432,
  "updated_at": 1698765432
}
```

**Example:**
```bash
curl http://localhost:8080/api/users/1
```

---

#### POST /api/users

Create a new user.

**Headers:**
- `X-CSRF-Token`: CSRF token (required)
- `Content-Type`: application/json

**Request Body:**
```json
{
  "username": "jane@example.com",
  "email": "jane@example.com",
  "password": "SecurePassword123!",
  "enabled": true
}
```

**Response:** `201 Created` or `400 Bad Request`

**Response Body:**
```json
{
  "id": 2,
  "username": "jane@example.com",
  "email": "jane@example.com",
  "enabled": true,
  "created_at": 1698765500,
  "updated_at": 1698765500
}
```

**Example:**
```bash
curl -X POST http://localhost:8080/api/users \
  -H "X-CSRF-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "jane@example.com",
    "email": "jane@example.com",
    "password": "SecurePassword123!",
    "enabled": true
  }'
```

---

#### PUT /api/users/{id}

Update an existing user.

**Path Parameters:**
- `id`: User ID (integer)

**Headers:**
- `X-CSRF-Token`: CSRF token (required)
- `Content-Type`: application/json

**Request Body:**
```json
{
  "email": "jane.doe@example.com",
  "enabled": false,
  "password": "NewPassword456!"
}
```

**Note:** All fields are optional. Only provided fields will be updated.

**Response:** `200 OK` or `404 Not Found`

**Example:**
```bash
curl -X PUT http://localhost:8080/api/users/2 \
  -H "X-CSRF-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

---

#### DELETE /api/users/{id}

Delete a user.

**Path Parameters:**
- `id`: User ID (integer)

**Headers:**
- `X-CSRF-Token`: CSRF token (required)

**Response:** `204 No Content` or `404 Not Found`

**Example:**
```bash
curl -X DELETE http://localhost:8080/api/users/2 \
  -H "X-CSRF-Token: $TOKEN"
```

---

### Message Queue

#### GET /api/queue

Get message queue status and pending messages.

**Query Parameters:**
- `limit`: Maximum messages to return (default: 100)
- `offset`: Pagination offset (default: 0)
- `status`: Filter by status (`pending`, `retry`, `failed`)

**Response:** `200 OK`

**Response Body:**
```json
{
  "queue_size": 15,
  "messages": [
    {
      "id": 42,
      "from_address": "sender@example.com",
      "to_address": "recipient@example.com",
      "priority": 0,
      "retry_count": 2,
      "max_retries": 5,
      "next_retry_at": 1698765600,
      "created_at": 1698765432,
      "last_error": "Connection timeout"
    }
  ]
}
```

**Example:**
```bash
curl "http://localhost:8080/api/queue?limit=10&status=retry"
```

---

### Filter Management

#### GET /api/filters

List all content filter rules.

**Response:** `200 OK`

**Response Body:**
```json
{
  "filters": [
    {
      "id": 1,
      "name": "Block spam subject",
      "rule_type": "subject",
      "pattern": "(?i)(viagra|cialis)",
      "action": "reject",
      "priority": 100,
      "enabled": true,
      "created_at": 1698765432
    }
  ],
  "total": 1
}
```

**Filter Types:**
- `subject`: Match email subject
- `from`: Match sender address
- `to`: Match recipient address
- `body`: Match message body
- `header`: Match specific header

**Filter Actions:**
- `reject`: Reject with 5xx
- `quarantine`: Move to quarantine
- `tag`: Add header tag
- `delete`: Silent drop

**Example:**
```bash
curl http://localhost:8080/api/filters
```

---

#### POST /api/filters

Create a new filter rule.

**Headers:**
- `X-CSRF-Token`: CSRF token (required)
- `Content-Type`: application/json

**Request Body:**
```json
{
  "name": "Block phishing",
  "rule_type": "subject",
  "pattern": "(?i)(verify your account|urgent.*password)",
  "action": "reject",
  "priority": 100,
  "enabled": true
}
```

**Response:** `201 Created` or `400 Bad Request`

**Example:**
```bash
curl -X POST http://localhost:8080/api/filters \
  -H "X-CSRF-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block phishing",
    "rule_type": "subject",
    "pattern": "(?i)(verify your account)",
    "action": "reject",
    "priority": 100,
    "enabled": true
  }'
```

---

#### DELETE /api/filters/{id}

Delete a filter rule.

**Path Parameters:**
- `id`: Filter ID (integer)

**Headers:**
- `X-CSRF-Token`: CSRF token (required)

**Response:** `204 No Content` or `404 Not Found`

**Example:**
```bash
curl -X DELETE http://localhost:8080/api/filters/1 \
  -H "X-CSRF-Token: $TOKEN"
```

---

### Message Search

#### GET /api/search

Search messages with full-text search.

**Query Parameters:**
- `q`: Search query (required)
- `limit`: Maximum results (default: 100)
- `offset`: Pagination offset (default: 0)
- `field`: Search field (`from`, `to`, `subject`, `body`, `all`)

**Response:** `200 OK`

**Response Body:**
```json
{
  "results": [
    {
      "message_id": "abc123",
      "from": "sender@example.com",
      "to": ["recipient@example.com"],
      "subject": "Meeting tomorrow",
      "timestamp": 1698765432,
      "score": 0.95
    }
  ],
  "total": 1,
  "took_ms": 12.5
}
```

**Example:**
```bash
curl "http://localhost:8080/api/search?q=meeting&field=subject&limit=20"
```

---

#### GET /api/search/stats

Get search index statistics.

**Response:** `200 OK`

**Response Body:**
```json
{
  "total_documents": 45230,
  "index_size_mb": 234.5,
  "last_updated": 1698765432,
  "avg_search_time_ms": 8.3
}
```

**Example:**
```bash
curl http://localhost:8080/api/search/stats
```

---

#### POST /api/search/rebuild

Rebuild the search index.

**Headers:**
- `X-CSRF-Token`: CSRF token (required)

**Response:** `202 Accepted`

**Response Body:**
```json
{
  "status": "rebuilding",
  "message": "Search index rebuild started"
}
```

**Example:**
```bash
curl -X POST http://localhost:8080/api/search/rebuild \
  -H "X-CSRF-Token: $TOKEN"
```

---

### Statistics

#### GET /api/stats

Get comprehensive server statistics (same as /stats on port 8081).

**Response:** `200 OK`

---

### Configuration

#### GET /api/config

Get current server configuration (read-only, sensitive values redacted).

**Response:** `200 OK`

**Response Body:**
```json
{
  "host": "0.0.0.0",
  "port": 2525,
  "max_connections": 100,
  "max_message_size": 10485760,
  "max_recipients": 100,
  "enable_tls": false,
  "enable_auth": true,
  "enable_greylist": false,
  "enable_dnsbl": false,
  "rate_limit_per_ip": 100,
  "rate_limit_per_user": 200
}
```

**Note:** Sensitive fields (TLS paths, webhook URLs) are redacted in the response.

**Example:**
```bash
curl http://localhost:8080/api/config
```

---

#### PUT /api/config

Update runtime configuration (limited fields).

**Headers:**
- `X-CSRF-Token`: CSRF token (required)
- `Content-Type`: application/json

**Request Body:**
```json
{
  "max_connections": 200,
  "enable_greylist": true
}
```

**Updatable Fields:**
- `max_connections`
- `enable_greylist`
- `enable_dnsbl`
- `rate_limit_per_ip`
- `rate_limit_per_user`

**Note:** Changes apply immediately without server restart (where supported).

**Response:** `200 OK` or `400 Bad Request`

**Example:**
```bash
curl -X PUT http://localhost:8080/api/config \
  -H "X-CSRF-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enable_greylist": true}'
```

---

### Logs

#### GET /api/logs

Retrieve recent server logs.

**Query Parameters:**
- `limit`: Maximum log entries (default: 100, max: 1000)
- `level`: Filter by log level (`debug`, `info`, `warn`, `error`, `critical`)
- `since`: Timestamp to retrieve logs from

**Response:** `200 OK`

**Response Body:**
```json
{
  "logs": [
    {
      "timestamp": 1698765432,
      "level": "INFO",
      "message": "Connection from 192.168.1.100: established"
    },
    {
      "timestamp": 1698765433,
      "level": "WARN",
      "message": "Rate limit exceeded for 10.0.0.1"
    }
  ],
  "total": 2
}
```

**Example:**
```bash
curl "http://localhost:8080/api/logs?limit=50&level=warn"
```

---

### Admin Interface

#### GET / or /admin

Serve web-based administration interface.

**Response:** `200 OK`
**Content-Type:** `text/html`

Provides a browser-based UI for managing users, filters, and viewing statistics.

---

## Error Responses

All errors return appropriate HTTP status codes with JSON bodies:

**Format:**
```json
{
  "error": "Error message description"
}
```

**Common Status Codes:**
- `400 Bad Request`: Invalid request body or parameters
- `403 Forbidden`: CSRF validation failed or permission denied
- `404 Not Found`: Resource not found
- `409 Conflict`: Resource already exists
- `500 Internal Server Error`: Server error
- `503 Service Unavailable`: Service degraded or unavailable

---

## Rate Limiting

API endpoints are subject to rate limiting:
- **Default Limit:** 100 requests/minute per IP
- **Response Header:** `X-RateLimit-Remaining: 95`
- **Rate Limit Exceeded:** `429 Too Many Requests`

---

## Security

### Authentication

Currently, the management API uses IP-based access control (localhost only). Future versions will support:
- API key authentication
- JWT tokens
- OAuth 2.0

### HTTPS

For production deployments, use a reverse proxy (nginx, Caddy) with TLS termination.

**Example nginx configuration:**
```nginx
server {
    listen 443 ssl;
    server_name api.example.com;

    ssl_certificate /etc/ssl/certs/api.crt;
    ssl_certificate_key /etc/ssl/private/api.key;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## See Also

- [Configuration Guide](./CONFIGURATION.md) - Server configuration
- [Database Schema](./DATABASE.md) - Database structure
- [Troubleshooting](./TROUBLESHOOTING.md) - Common issues and solutions
- [Deployment Guide](./DEPLOYMENT.md) - Production deployment

---

**Last Updated:** 2025-10-24
**API Version:** v0.28.0
