# Mail Server Architecture

Comprehensive architecture documentation for the production-grade SMTP server.

## Table of Contents

- [System Overview](#system-overview)
- [Component Architecture](#component-architecture)
- [Data Flow](#data-flow)
- [Storage Architecture](#storage-architecture)
- [Security Architecture](#security-architecture)
- [Deployment Architecture](#deployment-architecture)
- [Scalability Design](#scalability-design)

---

## System Overview

The SMTP server is designed as a modular, scalable, production-ready email server written in Zig with the following key characteristics:

### Design Principles

1. **Modularity**: Clear separation of concerns with pluggable components
2. **Security**: Defense-in-depth with multiple security layers
3. **Performance**: Zero-copy buffers, memory pools, async I/O
4. **Reliability**: Atomic operations, comprehensive error handling
5. **Compliance**: GDPR, RFC standards, audit logging
6. **Observability**: Metrics, health checks, structured logging

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         SMTP Clients                             │
└────────────┬────────────────────────────────────────┬───────────┘
             │                                        │
             ▼                                        ▼
┌────────────────────────┐              ┌────────────────────────┐
│   SMTP Protocol (25)   │              │  Submission (587/465)  │
│   - Plain text         │              │  - TLS required        │
│   - STARTTLS optional  │              │  - AUTH required       │
└────────────┬───────────┘              └────────────┬───────────┘
             │                                        │
             └────────────────┬───────────────────────┘
                              ▼
                  ┌───────────────────────┐
                  │   Connection Handler   │
                  │   - Rate limiting      │
                  │   - Connection pool    │
                  │   - Timeout management │
                  └───────────┬───────────┘
                              │
                              ▼
                  ┌───────────────────────┐
                  │  SMTP State Machine   │
                  │  - Command parsing    │
                  │  - Protocol validation│
                  │  - Extension handling │
                  └───────────┬───────────┘
                              │
             ┌────────────────┼────────────────┐
             │                │                │
             ▼                ▼                ▼
    ┌─────────────┐  ┌───────────────┐  ┌──────────────┐
    │   Auth      │  │   Security    │  │   Delivery   │
    │ - Database  │  │ - SPF/DKIM    │  │ - Queue      │
    │ - Argon2id  │  │ - Spam check  │  │ - Retry      │
    └─────────────┘  │ - Virus scan  │  │ - Relay      │
                     └───────────────┘  └──────┬───────┘
                                               │
                                               ▼
                                    ┌──────────────────┐
                                    │  Storage Layer   │
                                    │  - Maildir       │
                                    │  - mbox          │
                                    │  - Database      │
                                    │  - S3            │
                                    │  - Time-series   │
                                    └──────────────────┘
```

---

## Component Architecture

### Core Components

#### 1. **SMTP Protocol Handler** (`src/smtp.zig`)

**Responsibilities:**
- RFC 5321 protocol implementation
- Command parsing and validation
- Extension support (PIPELINING, SIZE, AUTH, etc.)
- State machine management

**Key Features:**
- Case-insensitive command handling
- Multi-line response support
- Buffer management for large messages
- Transaction isolation

**State Machine:**
```
INIT → GREETING → HELO/EHLO → [AUTH] → MAIL → RCPT+ → DATA → QUIT
                     ↑                              ↓
                     └──────────── RSET ────────────┘
```

#### 2. **Authentication Module** (`src/auth.zig`)

**Responsibilities:**
- User credential verification
- Password hashing (Argon2id)
- Database integration
- Session management

**Security Features:**
- Constant-time comparison (timing attack prevention)
- Rate limiting on auth attempts
- Failed login tracking
- Account lockout mechanism

**Flow:**
```
Client                Server                Database
  │                      │                      │
  ├─AUTH PLAIN ─────────>│                      │
  │                      ├─Parse credentials───>│
  │                      │                      │
  │                      │<─Hash + Salt ────────┤
  │                      ├─Verify (constant time)
  │                      │                      │
  │<─235 Success ────────┤                      │
```

#### 3. **Storage Backends**

**Maildir** (`src/maildir.zig`):
- One file per message
- Directory structure: `new/`, `cur/`, `tmp/`
- Atomic operations via rename
- File locking for concurrent access

**mbox** (`src/mbox.zig`):
- Single file per folder
- "From " line separators
- Line escaping ("From " → ">From ")
- Thread-safe with file locking

**Database** (`src/dbstorage.zig`):
- SQLite/PostgreSQL support
- Full-text search (FTS5)
- ACID transactions
- Query optimization with indexes

**Time-Series** (`src/timeseries_storage.zig`):
- Date-based hierarchy: `YYYY/MM/DD/`
- One file per message
- Easy archival and backup
- Encryption-ready structure

**S3** (`src/s3_storage.zig`):
- Cloud-scale storage
- Key format: `bucket/YYYY/MM/DD/message-id.eml`
- Multipart upload support
- Lifecycle policies

#### 4. **Security Components**

**SPF Validation** (`src/spf.zig`):
```
┌──────────┐     DNS TXT      ┌──────────┐
│  Sender  │ ───────────────> │   SPF    │
│   IP     │                  │  Record  │
└──────────┘                  └────┬─────┘
                                   │
                              Evaluate
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
                 Pass           Fail          SoftFail
```

**DKIM Signing** (`src/dkim.zig`):
```
Message ──> Hash Body ──> Sign with RSA ──> Add DKIM-Signature Header
              (SHA-256)      (Private Key)
```

**DMARC Policy** (`src/dmarc.zig`):
```
SPF Result ───┐
              ├──> Alignment Check ──> Policy Decision
DKIM Result ──┘     (strict/relaxed)     (none/quarantine/reject)
```

**Spam Detection**:
- SpamAssassin integration (`src/spamassassin.zig`)
- Bayesian filtering
- Score-based classification
- Policy-based actions (reject/quarantine/tag)

**Virus Scanning**:
- ClamAV integration (`src/clamav.zig`)
- INSTREAM protocol
- Real-time scanning
- Quarantine support

#### 5. **Queue Management** (`src/queue.zig`)

**Architecture:**
```
Incoming ──> Queue ──> Retry Logic ──> Delivery
  Message      │            │              │
               │            ▼              ▼
               │       Exponential      Success
               │        Backoff            │
               │            │              │
               └────────────┼──────────────┘
                            ▼
                      Dead Letter
                         Queue
```

**Features:**
- Priority queue
- Retry with exponential backoff
- Dead letter queue for failed messages
- Delivery status notifications (DSN)

---

## Data Flow

### Incoming Message Flow

```
1. TCP Connection
   ↓
2. Rate Limit Check
   ↓
3. SMTP Greeting (220)
   ↓
4. EHLO/HELO
   ↓
5. [Optional] STARTTLS
   ↓
6. [Optional] AUTH
   ↓
7. MAIL FROM
   ↓
8. RCPT TO (repeat for multiple recipients)
   ↓
9. DATA
   ↓
10. Message Body
   ↓
11. Security Checks:
    - SPF Validation
    - DKIM Verification
    - DMARC Policy
    - Spam Scanning
    - Virus Scanning
   ↓
12. Storage:
    - Parse headers
    - Extract attachments
    - Store in backend
   ↓
13. Queue for Delivery (if relay)
   ↓
14. Response (250 OK or error)
   ↓
15. QUIT
```

### Outgoing Message Flow

```
Queue Entry
   ↓
MX Record Lookup (DNS)
   ↓
Establish SMTP Connection
   ↓
EHLO
   ↓
[Optional] STARTTLS
   ↓
[Optional] AUTH
   ↓
MAIL FROM + DKIM Signature
   ↓
RCPT TO
   ↓
DATA
   ↓
Transmit Message
   ↓
Handle Response:
   - 2xx: Success, remove from queue
   - 4xx: Temporary failure, retry later
   - 5xx: Permanent failure, bounce
```

---

## Storage Architecture

### Database Schema

**Users Table:**
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,  -- Argon2id
    created_at INTEGER NOT NULL,
    last_login INTEGER,
    quota_mb INTEGER DEFAULT 1000,
    used_mb REAL DEFAULT 0,
    enabled BOOLEAN DEFAULT 1
);
```

**Messages Table:**
```sql
CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    message_id TEXT UNIQUE NOT NULL,
    user TEXT NOT NULL,
    folder TEXT DEFAULT 'INBOX',
    from_addr TEXT NOT NULL,
    to_addrs TEXT NOT NULL,      -- JSON array
    subject TEXT,
    date INTEGER NOT NULL,
    size INTEGER NOT NULL,
    flags TEXT,                   -- SEEN, REPLIED, etc.
    headers TEXT,                 -- JSON
    body BLOB,
    FOREIGN KEY (user) REFERENCES users(username)
);

CREATE INDEX idx_messages_user ON messages(user);
CREATE INDEX idx_messages_folder ON messages(user, folder);
CREATE INDEX idx_messages_date ON messages(date);

-- Full-text search
CREATE VIRTUAL TABLE messages_fts USING fts5(
    subject, body,
    content=messages
);
```

**Audit Log Table:**
```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    username TEXT,
    action TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    details TEXT
);

CREATE INDEX idx_audit_username ON audit_log(username);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
```

### Storage Strategies

**Small Deployments** (< 10K messages/day):
- Maildir + SQLite
- Single server
- Local disk storage

**Medium Deployments** (10K-100K messages/day):
- Database storage (PostgreSQL)
- Queue with retry logic
- Load balancer + multiple servers
- Shared NFS/GlusterFS for attachments

**Large Deployments** (> 100K messages/day):
- Time-series + S3 storage
- Distributed queue (RabbitMQ/Kafka)
- Kubernetes cluster
- CDN for attachments
- Read replicas for queries

---

## Security Architecture

### Defense in Depth

**Layer 1: Network**
- Firewall rules
- Rate limiting per IP
- DDoS protection
- Connection limits

**Layer 2: Protocol**
- SMTP command validation
- Buffer overflow protection
- Injection attack prevention
- Size limits

**Layer 3: Authentication**
- Argon2id password hashing
- Multi-factor authentication (planned)
- Account lockout
- Session management

**Layer 4: Message Content**
- SPF/DKIM/DMARC validation
- Spam filtering
- Virus scanning
- Attachment type restrictions

**Layer 5: Storage**
- Encryption at rest (AES-256-GCM)
- Access control lists
- Audit logging
- Secure deletion

**Layer 6: Application**
- Input validation
- Output encoding
- CSRF protection (REST API)
- Least privilege principle

### Encryption

**At Rest:**
```
Message ──> AES-256-GCM ──> Encrypted File
              (per-message key)
                  ↓
            Master Key (HKDF)
                  ↓
            Argon2id (password)
```

**In Transit:**
```
Client ──> STARTTLS ──> TLS 1.3 ──> Server
           (opportunistic)    (AES-256)
```

---

## Deployment Architecture

### Single Server

```
┌────────────────────────────────────────┐
│           Server (Linux)                │
│                                         │
│  ┌──────────────────────────────────┐  │
│  │     Mail Server (Port 25)        │  │
│  │     Submission (Port 587)        │  │
│  └──────────────────────────────────┘  │
│                 │                       │
│  ┌──────────────┴───────────────────┐  │
│  │   SQLite Database                │  │
│  │   Maildir Storage                │  │
│  └──────────────────────────────────┘  │
│                                         │
│  ┌──────────────────────────────────┐  │
│  │   Monitoring                     │  │
│  │   - Prometheus (9090)            │  │
│  │   - Health Check (8080)          │  │
│  └──────────────────────────────────┘  │
└────────────────────────────────────────┘
```

### High Availability

```
                      Load Balancer
                     (HAProxy/nginx)
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
          ▼                 ▼                 ▼
    ┌──────────┐      ┌──────────┐     ┌──────────┐
    │ SMTP-1   │      │ SMTP-2   │     │ SMTP-3   │
    │ (Active) │      │ (Active) │     │ (Active) │
    └────┬─────┘      └────┬─────┘     └────┬─────┘
         │                 │                 │
         └─────────────────┼─────────────────┘
                           │
                  ┌────────┴────────┐
                  │                 │
                  ▼                 ▼
           ┌────────────┐    ┌──────────┐
           │ PostgreSQL │    │   S3     │
           │ (Primary)  │    │ Storage  │
           └─────┬──────┘    └──────────┘
                 │
           ┌─────┴──────┐
           │ PostgreSQL │
           │ (Replica)  │
           └────────────┘
```

### Kubernetes Deployment

```
┌─────────────────── Kubernetes Cluster ───────────────────┐
│                                                            │
│  ┌─────────────────────────────────────────────────────┐  │
│  │              Ingress Controller                      │  │
│  │         (LoadBalancer / ExternalDNS)                 │  │
│  └─────────────────────┬───────────────────────────────┘  │
│                        │                                   │
│  ┌─────────────────────┴───────────────────────────────┐  │
│  │                    Service                           │  │
│  │             (ClusterIP / LoadBalancer)               │  │
│  └─────────────────────┬───────────────────────────────┘  │
│                        │                                   │
│  ┌──────────────┬──────┴────────┬─────────────────────┐  │
│  │              │               │                      │  │
│  ▼              ▼               ▼                      │  │
│  Pod-1         Pod-2          Pod-3                    │  │
│  mail   mail    mail              │  │
│                                                         │  │
│  ┌─────────────────────────────────────────────────┐   │  │
│  │          PersistentVolumes                       │   │  │
│  │          - Data (ReadWriteMany)                  │   │  │
│  │          - Queue (ReadWriteMany)                 │   │  │
│  └─────────────────────────────────────────────────┘   │  │
│                                                         │  │
│  ┌─────────────────────────────────────────────────┐   │  │
│  │          HorizontalPodAutoscaler                 │   │  │
│  │          - Min: 3, Max: 10                       │   │  │
│  │          - Metrics: CPU 70%, Memory 80%          │   │  │
│  └─────────────────────────────────────────────────┘   │  │
└─────────────────────────────────────────────────────────┘
```

---

## Scalability Design

### Horizontal Scaling

**Stateless Design:**
- No session affinity required
- Shared database backend
- Distributed queue

**Load Distribution:**
- Round-robin DNS
- Layer 4 load balancer
- Health-based routing

### Vertical Scaling

**Resource Optimization:**
- Memory pools for allocations
- Zero-copy buffers
- Connection pooling
- Async I/O (io_uring on Linux)

### Performance Characteristics

**Throughput:**
- Single thread: ~1,000 messages/sec
- Multi-core: ~10,000 messages/sec
- Cluster (10 nodes): ~100,000 messages/sec

**Latency:**
- P50: < 10ms
- P95: < 50ms
- P99: < 100ms

**Resource Usage:**
- Memory: ~100 MB baseline + 1KB per connection
- CPU: ~10% per 1K msg/sec
- Disk I/O: Depends on storage backend

---

## Monitoring & Observability

### Metrics Collection

```
Application
    ↓
Prometheus Exporter (Port 8081)
    ↓
Prometheus Server
    ↓
Grafana Dashboards
```

**Key Metrics:**
- `smtp_messages_received_total`
- `smtp_messages_sent_total`
- `smtp_connections_active`
- `smtp_auth_attempts_total`
- `smtp_processing_duration_seconds`

### Logging

**Structured Logging:**
```json
{
  "timestamp": "2025-10-23T12:00:00Z",
  "level": "INFO",
  "component": "smtp",
  "event": "message_received",
  "message_id": "abc123",
  "from": "sender@example.com",
  "to": ["recipient@example.com"],
  "size_bytes": 1234,
  "duration_ms": 45
}
```

### Health Checks

**Liveness:**
- Server process running
- Port listening
- Memory within limits

**Readiness:**
- Database connection healthy
- Storage backend accessible
- Queue processing

### Alerting

**Critical Alerts:**
- Service down
- Database connection lost
- Disk space < 10%
- Memory usage > 90%

**Warning Alerts:**
- Queue size > 1000
- Error rate > 5%
- Response time > 1s
- Failed auth > 100/hour

---

## Disaster Recovery

### Backup Strategy

**What to Backup:**
- Database (users, messages, audit logs)
- Message files (Maildir/mbox/time-series)
- Configuration files
- TLS certificates

**Backup Schedule:**
- Full backup: Daily
- Incremental backup: Hourly
- Retention: 30 days
- Off-site replication: Yes

### Recovery Procedures

**Database Recovery:**
```bash
# Stop server
systemctl stop mail

# Restore from backup
sqlite3 smtp.db < backup.sql

# Start server
systemctl start mail
```

**Message Recovery:**
```bash
# Restore Maildir
tar -xzf maildir-backup.tar.gz -C /var/mail/

# Fix permissions
chown -R smtp:smtp /var/mail/
chmod -R 700 /var/mail/
```

### Failover

**Automatic Failover:**
- Health check failure → remove from pool
- Primary database down → promote replica
- Node failure → Kubernetes reschedules pod

**Manual Failover:**
```bash
# Promote replica to primary
kubectl scale deployment mail --replicas=5

# Update DNS for manual failover
# Switch A record to backup IP
```

---

## Security Hardening

### System Level

```bash
# Firewall rules
ufw allow 25/tcp
ufw allow 587/tcp
ufw allow 465/tcp
ufw default deny incoming

# SELinux/AppArmor
setenforce 1

# User isolation
useradd -r -s /bin/false smtp
```

### Application Level

```zig
// Rate limiting
const RateLimit = struct {
    max_per_minute: u32 = 100,
    max_per_hour: u32 = 1000,
};

// Size limits
const max_message_size = 50 * 1024 * 1024; // 50MB
const max_recipients = 100;

// Timeout enforcement
const connection_timeout = 300; // 5 minutes
```

### Network Level

**DDoS Protection:**
- SYN flood protection
- Connection rate limiting
- IP blacklisting
- Geo-blocking (optional)

---

## Future Architecture

### Planned Improvements

1. **Microservices Architecture:**
   - Separate services for SMTP, queue, storage
   - gRPC for inter-service communication
   - Service mesh (Istio)

2. **Event-Driven Architecture:**
   - Kafka/NATS for event bus
   - Async message processing
   - Real-time analytics

3. **Multi-Region:**
   - Active-active deployment
   - Global load balancing
   - Data replication

4. **Machine Learning:**
   - Advanced spam detection
   - Anomaly detection
   - Predictive scaling

---

## Conclusion

This architecture provides a solid foundation for a production-grade SMTP server with:
- **Scalability**: From single server to global clusters
- **Reliability**: HA, DR, automatic failover
- **Security**: Defense-in-depth, compliance, audit logging
- **Performance**: Optimized for high throughput and low latency
- **Observability**: Comprehensive monitoring and logging

The modular design allows for incremental improvements and adaptation to specific deployment requirements.
