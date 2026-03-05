# Mail Server Security Guide

**Version:** v0.28.0
**Last Updated:** 2025-10-24
**Status:** Production Ready

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Environment Variables](#environment-variables)
4. [TLS/SSL Configuration](#tlsssl-configuration)
5. [Rate Limiting](#rate-limiting)
6. [Path Security](#path-security)
7. [Input Validation](#input-validation)
8. [Security Monitoring](#security-monitoring)
9. [Best Practices](#best-practices)
10. [Incident Response](#incident-response)

---

## Overview

This SMTP server implements comprehensive security measures including:

- ✅ **Authentication** across all protocols (SMTP, IMAP, POP3, ActiveSync, CalDAV)
- ✅ **Path Traversal Prevention** for all file operations
- ✅ **Input Validation** for usernames, headers, and messages
- ✅ **Rate Limiting** to prevent abuse
- ✅ **TLS/SSL Encryption** for secure communication
- ✅ **Security Logging** for audit trails

---

## Authentication

### Protocols with Authentication

All protocols now require proper authentication:

#### IMAP (RFC 3501)
- **Location:** `src/protocol/imap.zig:336-360`
- **Method:** LOGIN command with username/password
- **Features:**
  - Credential verification via AuthBackend
  - State validation (prevents re-authentication)
  - Failed attempt logging
  - Argon2id password hashing

#### POP3 (RFC 1939)
- **Location:** `src/protocol/pop3.zig:134-164`
- **Method:** USER/PASS command sequence
- **Features:**
  - Two-step authentication
  - Username capture before password
  - Secure credential validation
  - Mailbox locking after authentication

#### ActiveSync
- **Location:** `src/protocol/activesync.zig:258-276`
- **Method:** HTTP Basic Authentication
- **Features:**
  - Base64 credential decoding
  - HTTP 401 responses on failure
  - Authorization header parsing
  - Per-request authentication

#### CalDAV/CardDAV
- **Location:** `src/protocol/caldav.zig:194-209`
- **Method:** HTTP Basic Authentication
- **Features:**
  - WWW-Authenticate headers
  - Digest auth support (optional)
  - Per-request validation
  - Resource-level authorization

### Password Security

**Hashing Algorithm:** Argon2id
**Parameters:**
- Time cost (t): 3
- Memory cost (m): 65536 (64 MB)
- Parallelism (p): 4
- Salt: Random 16 bytes per password

**Implementation:**
```zig
// Password hashing (automatic)
const password_hash = try password_hasher.hashPassword(password);

// Password verification (automatic)
const valid = try password_hasher.verifyPassword(password, stored_hash);
```

### Authentication Backend

**File:** `src/auth/auth.zig`

**Features:**
- Centralized credential verification
- Database integration
- Account status checking (enabled/disabled)
- Last login timestamp tracking
- Basic Auth header parsing

**Usage:**
```zig
var auth_backend = auth.AuthBackend.init(allocator, database);

// Verify credentials
const valid = try auth_backend.verifyCredentials(username, password);

// Verify HTTP Basic Auth
const username = try auth_backend.verifyBasicAuth(auth_header);
```

---

## Environment Variables

### Required for Production

```bash
# AWS S3 (if using S3 storage)
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-east-1"  # optional, defaults to us-east-1

# TLS/SSL Certificates
export SMTP_TLS_CERT="/path/to/cert.pem"
export SMTP_TLS_KEY="/path/to/key.pem"

# Database (if not using default)
export SMTP_DB_PATH="/var/lib/mail/smtp.db"

# Optional: JSON Logging
export SMTP_ENABLE_JSON_LOGGING="true"
```

### Testing Environment

```bash
# For running tests with S3 integration
export AWS_ACCESS_KEY_ID="test-key"
export AWS_SECRET_ACCESS_KEY="test-secret"

# Tests will skip if credentials not provided
```

### Security Notes

- ⚠️ **Never** commit `.env` files to version control
- ⚠️ **Never** hardcode credentials in source code
- ✅ Use environment variables or secure vaults
- ✅ Rotate credentials regularly
- ✅ Use different credentials for dev/staging/production

---

## TLS/SSL Configuration

### Certificate Setup

**Generate Self-Signed Certificate (Development)**
```bash
./scripts/generate-cert.sh
```

**Production Certificates**
```bash
# Let's Encrypt (recommended)
certbot certonly --standalone -d mail.example.com

# Update environment
export SMTP_TLS_CERT="/etc/letsencrypt/live/mail.example.com/fullchain.pem"
export SMTP_TLS_KEY="/etc/letsencrypt/live/mail.example.com/privkey.pem"
```

### TLS Configuration

```bash
# Enable TLS
export SMTP_ENABLE_TLS="true"
export SMTP_TLS_CERT="/path/to/cert.pem"
export SMTP_TLS_KEY="/path/to/key.pem"

# Ports
# - 25: SMTP (STARTTLS)
# - 465: SMTPS (implicit TLS)
# - 587: Submission (STARTTLS)
# - 993: IMAPS (implicit TLS)
# - 995: POP3S (implicit TLS)
```

### Security Settings

- ✅ TLS 1.2+ only (TLS 1.0/1.1 disabled)
- ✅ Strong cipher suites
- ✅ Perfect Forward Secrecy (PFS)
- ✅ Certificate validation
- ✅ STARTTLS support for SMTP

---

## Rate Limiting

### Configuration

**File:** `src/auth/rate_limiter.zig`

```zig
pub const RateLimitConfig = struct {
    max_requests: u32 = 100,       // Per time window
    window_seconds: u64 = 60,      // Time window
    cleanup_interval: u64 = 300,   // Cleanup old entries
};
```

### Protection Levels

**IP-Based Rate Limiting:**
- Default: 100 requests/minute per IP
- Prevents DDoS attacks
- Automatic cleanup

**User-Based Rate Limiting:**
- Default: 200 requests/minute per user
- Prevents account abuse
- Authentication required

**Failed Login Protection:**
- Logs all failed attempts
- Alerts after threshold
- Temporary lockout (optional)

### Monitoring

```zig
// Security logging (automatic)
std.log.warn("Failed IMAP login attempt for user: {s}", .{username});
std.log.info("Successful POP3 login for user: {s}", .{username});
```

---

## Path Security

### Path Sanitization

**File:** `src/core/path_sanitizer.zig`

**Features:**
- ✅ Prevents `../` directory traversal
- ✅ Rejects absolute paths from users
- ✅ Resolves symlinks
- ✅ Validates canonical paths
- ✅ Sanitizes filenames
- ✅ Null byte filtering

### Protected Modules

1. **Mbox Storage** (`src/storage/mbox.zig`)
   - Path validation on initialization
   - Relative path sanitization

2. **Backup Manager** (`src/storage/backup.zig`)
   - Source and destination path validation
   - Prevents backup to unauthorized locations

3. **Attachments** (`src/message/attachment.zig`)
   - Filename sanitization
   - Directory path validation
   - Combined security checks

### Usage Example

```zig
const path_sanitizer = @import("core/path_sanitizer.zig");

// Sanitize a path
const safe_path = try path_sanitizer.PathSanitizer.sanitizePath(
    allocator,
    "/var/mail",  // base directory
    user_path     // user-provided path
);
defer allocator.free(safe_path);

// Sanitize a filename
const safe_filename = try path_sanitizer.PathSanitizer.sanitizeFilename(
    allocator,
    user_filename
);
defer allocator.free(safe_filename);
```

### Security Tests

All path operations include security tests:
- ✅ Path traversal attempts
- ✅ Absolute path rejection
- ✅ Null byte injection
- ✅ Symlink attacks
- ✅ Unicode/encoding tricks

---

## Input Validation

### Username Validation

**File:** `src/api/api.zig:10-40`

**Rules:**
- Length: 1-64 characters
- Characters: alphanumeric, `_`, `-`, `.`
- No leading/trailing `.` or `-`
- No consecutive dots
- Case-sensitive

**Examples:**
```
✅ Valid:   "john.doe", "user_123", "admin-2024"
❌ Invalid: ".user", "user..name", "user@#$%", ""
```

### Header Injection Protection

**File:** `src/auth/security.zig:360-369`

**Protection:**
```zig
// Blocks ALL CRLF sequences
if (std.mem.indexOf(u8, input, "\r\n") != null) return false;
if (std.mem.indexOf(u8, input, "\n") != null) return false;
if (std.mem.indexOf(u8, input, "\r") != null) return false;
```

**Prevents:**
- Email header injection
- SMTP command injection
- HTTP header splitting

### WebSocket Message Size

**File:** `src/protocol/websocket.zig:317-330`

**Limits:**
- Configurable: `config.max_message_size` (default: 1MB)
- Absolute maximum: 16MB (hard limit)
- Close frame 1009 sent on violation

**Configuration:**
```zig
const ws_config = WebSocketConfig{
    .max_message_size = 1024 * 1024,  // 1MB
    // ... other options
};
```

---

## Security Monitoring

### Log Categories

**Authentication Events:**
```
[INFO]  Successful IMAP login for user: alice
[WARN]  Failed POP3 login attempt for user: bob
[ERROR] Authentication error: InvalidCredentials
```

**Path Security:**
```
[WARN]  Path traversal attempt detected (..): ../../etc/passwd
[WARN]  Absolute path not allowed: /etc/shadow
[INFO]  Saving attachment to: /var/mail/attachments/safe-file.pdf
```

**Input Validation:**
```
[WARN]  Invalid username length: 0
[WARN]  Invalid character in username: @ (0x40)
[WARN]  WebSocket message too large: 2000000 bytes (max: 1048576)
```

**Rate Limiting:**
```
[WARN]  Rate limit exceeded for IP: 192.168.1.100
[INFO]  Rate limit cleanup: removed 42 expired entries
```

### Metrics to Track

1. **Authentication Metrics**
   - Success rate per protocol
   - Failed attempts per user/IP
   - Average authentication time
   - Account lockouts

2. **Security Events**
   - Path traversal attempts
   - Header injection attempts
   - Rate limit violations
   - Input validation failures

3. **Performance Metrics**
   - Request latency
   - Connection count
   - Message throughput
   - Error rates

### Alerting Thresholds

```bash
# Failed Authentication
> 10 failed attempts from single IP in 1 minute → ALERT

# Path Traversal
> 5 path traversal attempts in 1 hour → ALERT

# Input Validation
> 100 validation errors in 1 hour → INVESTIGATE

# Performance
Authentication time > 1 second → WARNING
Memory usage > 80% → ALERT
```

---

## Best Practices

### 1. Authentication

✅ **DO:**
- Use strong passwords (12+ characters)
- Enable authentication for all protocols
- Rotate passwords regularly
- Use Argon2id for hashing
- Log all authentication events

❌ **DON'T:**
- Use default/weak passwords
- Share credentials
- Disable authentication in production
- Store passwords in plain text
- Ignore failed login attempts

### 2. Network Security

✅ **DO:**
- Enable TLS/SSL for all connections
- Use valid certificates in production
- Configure firewall rules
- Limit exposed ports
- Use fail2ban for intrusion prevention

❌ **DON'T:**
- Use self-signed certs in production
- Expose unnecessary ports
- Allow unencrypted connections
- Skip certificate validation

### 3. File System

✅ **DO:**
- Use path sanitization for all file operations
- Set proper file permissions (600 for private, 644 for public)
- Regular backups
- Monitor disk usage
- Validate all user-provided paths

❌ **DON'T:**
- Trust user-provided paths
- Use world-writable directories
- Skip backup verification
- Ignore disk space warnings

### 4. Monitoring

✅ **DO:**
- Enable comprehensive logging
- Set up log aggregation
- Configure alerts for security events
- Review logs regularly
- Monitor resource usage

❌ **DON'T:**
- Disable logging in production
- Ignore security alerts
- Log sensitive data (passwords, keys)
- Skip log rotation

---

## Incident Response

### Security Incident Levels

**Level 1: Low** (Information)
- Single failed login
- Validation error
- Examples: typo in username

**Level 2: Medium** (Warning)
- Multiple failed logins (< 10)
- Path traversal attempt
- Rate limit reached
- Examples: scanning, probing

**Level 3: High** (Alert)
- Sustained attack (> 10 attempts)
- Authentication bypass attempt
- Database compromise indication
- Examples: brute force, SQL injection

**Level 4: Critical** (Emergency)
- Active breach
- Data exfiltration
- System compromise
- Examples: unauthorized access confirmed

### Response Procedures

**Step 1: Detection**
```bash
# Check logs for suspicious activity
tail -f /var/log/mail/security.log | grep -i "failed\|attack\|injection"

# Monitor authentication failures
grep "Failed.*login" /var/log/mail/*.log | wc -l
```

**Step 2: Containment**
```bash
# Block malicious IP
iptables -A INPUT -s <MALICIOUS_IP> -j DROP

# Disable compromised account
# (Update database: enabled = false)

# Restart server if needed
systemctl restart mail
```

**Step 3: Investigation**
```bash
# Collect evidence
cp /var/log/mail/security.log /incident/evidence/

# Check for unauthorized access
grep "Successful.*login" /var/log/mail/*.log

# Review file changes
find /var/mail -type f -mtime -1 -ls
```

**Step 4: Recovery**
```bash
# Restore from backup if needed
./scripts/restore-backup.sh <BACKUP_ID>

# Force password reset for affected users
# (Update database: force_password_reset = true)

# Update firewall rules
# (Add permanent blocks)
```

**Step 5: Post-Incident**
- Document the incident
- Update security procedures
- Conduct root cause analysis
- Implement preventive measures
- Notify affected users if required

### Emergency Contacts

```
Security Team: security@example.com
On-Call: +1-555-SECURITY
Incident Hotline: +1-555-INCIDENT
```

---

## Security Checklist

### Pre-Production

- [ ] All authentication bypasses fixed
- [ ] TLS/SSL certificates configured
- [ ] Environment variables set
- [ ] Rate limiting configured
- [ ] Path sanitization enabled
- [ ] Input validation active
- [ ] Security logging enabled
- [ ] Monitoring configured
- [ ] Backups automated
- [ ] Incident response plan ready

### Production

- [ ] All ports firewalled
- [ ] fail2ban configured
- [ ] Log aggregation active
- [ ] Alerts configured
- [ ] Backups verified
- [ ] Certificates valid
- [ ] Regular security audits scheduled
- [ ] Patch management process

### Ongoing

- [ ] Weekly log review
- [ ] Monthly security audit
- [ ] Quarterly penetration test
- [ ] Annual security review
- [ ] Continuous monitoring
- [ ] Regular updates
- [ ] Security training
- [ ] Incident drills

---

## Additional Resources

### Documentation
- [Security Audit Report](SECURITY_AUDIT.md)
- [Security Implementation Plan](SECURITY_IMPLEMENTATION_PLAN.md)
- [Configuration Guide](CONFIGURATION.md)
- [API Reference](API_REFERENCE.md)

### External Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Database](https://cwe.mitre.org/)
- [Zig Security Guide](https://ziglang.org/documentation/master/#Security)

### RFCs
- RFC 5321: SMTP
- RFC 3501: IMAP
- RFC 1939: POP3
- RFC 4791: CalDAV
- RFC 6455: WebSocket

---

**Document Version:** 1.0
**Last Review:** 2025-10-24
**Next Review:** 2025-11-24
**Maintained By:** Security Team
