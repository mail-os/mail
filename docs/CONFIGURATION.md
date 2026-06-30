# Configuration Guide

**Version:** v0.28.0
**Date:** 2025-10-24

## Overview

The SMTP server supports configuration through multiple methods:
1. **Configuration Profiles** (development, testing, staging, production)
2. **Environment Variables** (highest priority overrides)
3. **Command-line Arguments**
4. **Default Values** (lowest priority)

## Configuration Priority

```
Environment Variables > Command-line Args > Profile Defaults > System Defaults
```

## Configuration Profiles

The server includes built-in configuration profiles optimized for different environments. Profiles provide sensible defaults for development, testing, staging, and production use cases.

### Available Profiles

- **development** - Relaxed limits, verbose logging, quick iteration
- **testing** - Minimal resources, fast failures, deterministic behavior
- **staging** - Production-like settings for pre-production testing
- **production** - Optimized for throughput, security, and reliability

### Using Profiles

Set the `SMTP_PROFILE` environment variable to activate a profile:

```bash
# Development mode
SMTP_PROFILE=development ./mail

# Production mode
SMTP_PROFILE=production ./mail

# Testing mode (used by test suite)
SMTP_PROFILE=testing ./mail
```

You can also use short aliases: `dev`, `test`, `stage`, `prod`

### Profile Configuration Details

See `src/core/config_profiles.zig` for complete profile definitions.

#### Development Profile
- SMTP Port: 2525 (non-privileged)
- Max Connections: 100
- Log Level: debug
- TLS: Optional
- Auth: Optional
- Features: Spam filter enabled, virus scan disabled, greylist disabled
- Purpose: Fast iteration, verbose debugging

#### Testing Profile
- SMTP Port: 0 (random)
- Max Connections: 10
- Log Level: warn (minimal noise)
- TLS: Disabled
- Auth: Disabled
- Features: All filters disabled for deterministic tests
- Purpose: Fast, isolated unit/integration tests

#### Staging Profile
- SMTP Port: 25
- Max Connections: 500
- Log Level: info
- TLS: Required
- Auth: Required
- Features: All security features enabled
- Purpose: Pre-production validation

#### Production Profile
- SMTP Port: 25
- Max Connections: 2000
- Log Level: info
- TLS: Required (TLS 1.3 minimum)
- Auth: Required
- Features: All security features enabled, io_uring enabled (Linux)
- Purpose: Maximum throughput and security

### Validation Mode

Validate your configuration without starting the server:

```bash
./mail --validate-only

# With custom profile
SMTP_PROFILE=production ./mail --validate-only

# With environment overrides
SMTP_PROFILE=production SMTP_MAX_CONNECTIONS=5000 ./mail --validate-only
```

This checks:
- All configuration values are within valid ranges
- Required files/paths exist
- Port numbers are valid
- Timeout values are reasonable
- Profile is valid

## Quick Start

### Basic Setup

```bash
# Minimal configuration
SMTP_HOST=0.0.0.0 \
SMTP_PORT=2525 \
./mail
```

### Production Setup

```bash
# Production configuration
SMTP_HOST=0.0.0.0 \
SMTP_PORT=2525 \
SMTP_HOSTNAME=mail.example.com \
SMTP_MAX_CONNECTIONS=500 \
SMTP_ENABLE_AUTH=true \
SMTP_DB_PATH=/var/lib/mail/smtp.db \
SMTP_ENABLE_DNSBL=true \
SMTP_ENABLE_GREYLIST=true \
SMTP_WEBHOOK_URL=https://api.example.com/webhook \
./mail
```

## Configuration Reference

### Server Settings

#### SMTP_HOST
- **Description:** IP address to bind to
- **Type:** String (IP address)
- **Default:** `0.0.0.0` (all interfaces)
- **Examples:**
  ```bash
  SMTP_HOST=0.0.0.0        # Listen on all interfaces
  SMTP_HOST=127.0.0.1      # Listen on localhost only
  SMTP_HOST=192.168.1.100  # Listen on specific IP
  ```

#### SMTP_PORT
- **Description:** Port to listen on
- **Type:** Integer (1-65535)
- **Default:** `2525` (non-privileged)
- **Common Values:**
  - `25` - Standard SMTP (requires root)
  - `587` - SMTP Submission (requires root)
  - `2525` - Development/non-privileged
- **Examples:**
  ```bash
  SMTP_PORT=2525   # Development
  SMTP_PORT=25     # Production (with TLS proxy)
  ```

#### SMTP_HOSTNAME
- **Description:** Server hostname for SMTP greeting
- **Type:** String
- **Default:** `localhost`
- **Examples:**
  ```bash
  SMTP_HOSTNAME=mail.example.com
  SMTP_HOSTNAME=smtp.company.org
  ```

---

### Connection Limits

#### SMTP_MAX_CONNECTIONS
- **Description:** Maximum concurrent connections
- **Type:** Integer
- **Default:** `100`
- **Recommended:**
  - Small servers: 100-500
  - Medium servers: 500-2000
  - Large servers: 2000-10000
- **Examples:**
  ```bash
  SMTP_MAX_CONNECTIONS=100    # Small deployment
  SMTP_MAX_CONNECTIONS=1000   # Medium deployment
  SMTP_MAX_CONNECTIONS=5000   # Large deployment
  ```

---

### Timeout Configuration

The server supports granular timeout settings for different phases of SMTP communication.

#### SMTP_TIMEOUT_SECONDS
- **Description:** General connection timeout
- **Type:** Integer (seconds)
- **Default:** `300` (5 minutes)
- **Range:** 60-3600 seconds
- **Purpose:** Overall connection lifetime limit
- **Examples:**
  ```bash
  SMTP_TIMEOUT_SECONDS=300    # 5 minutes (default)
  SMTP_TIMEOUT_SECONDS=600    # 10 minutes (relaxed)
  ```

#### SMTP_DATA_TIMEOUT_SECONDS
- **Description:** Timeout for DATA command (message upload)
- **Type:** Integer (seconds)
- **Default:** `600` (10 minutes)
- **Range:** 300-3600 seconds
- **Purpose:** Allow time for large message uploads
- **Examples:**
  ```bash
  SMTP_DATA_TIMEOUT_SECONDS=600   # 10 minutes (default)
  SMTP_DATA_TIMEOUT_SECONDS=1200  # 20 minutes (large messages)
  SMTP_DATA_TIMEOUT_SECONDS=300   # 5 minutes (strict)
  ```

#### SMTP_COMMAND_TIMEOUT_SECONDS
- **Description:** Timeout between SMTP commands
- **Type:** Integer (seconds)
- **Default:** `300` (5 minutes)
- **Range:** 60-600 seconds
- **Purpose:** Prevent idle connections
- **Examples:**
  ```bash
  SMTP_COMMAND_TIMEOUT_SECONDS=300  # 5 minutes (default)
  SMTP_COMMAND_TIMEOUT_SECONDS=120  # 2 minutes (strict)
  ```

#### SMTP_GREETING_TIMEOUT_SECONDS
- **Description:** Timeout for initial client greeting
- **Type:** Integer (seconds)
- **Default:** `30` (30 seconds)
- **Range:** 10-120 seconds
- **Purpose:** Quickly disconnect slow/broken clients
- **Examples:**
  ```bash
  SMTP_GREETING_TIMEOUT_SECONDS=30   # 30 seconds (default)
  SMTP_GREETING_TIMEOUT_SECONDS=60   # 1 minute (relaxed)
  SMTP_GREETING_TIMEOUT_SECONDS=10   # 10 seconds (strict)
  ```

#### Timeout Configuration Examples

**Conservative (relaxed timeouts):**
```bash
SMTP_TIMEOUT_SECONDS=600
SMTP_DATA_TIMEOUT_SECONDS=1200
SMTP_COMMAND_TIMEOUT_SECONDS=600
SMTP_GREETING_TIMEOUT_SECONDS=60
```

**Balanced (recommended):**
```bash
SMTP_TIMEOUT_SECONDS=300
SMTP_DATA_TIMEOUT_SECONDS=600
SMTP_COMMAND_TIMEOUT_SECONDS=300
SMTP_GREETING_TIMEOUT_SECONDS=30
```

**Aggressive (strict timeouts):**
```bash
SMTP_TIMEOUT_SECONDS=120
SMTP_DATA_TIMEOUT_SECONDS=300
SMTP_COMMAND_TIMEOUT_SECONDS=120
SMTP_GREETING_TIMEOUT_SECONDS=10
```

---

### Message Limits

#### SMTP_MAX_MESSAGE_SIZE
- **Description:** Maximum message size in bytes
- **Type:** Integer
- **Default:** `10485760` (10 MB)
- **Recommended:** 10MB - 50MB
- **Examples:**
  ```bash
  SMTP_MAX_MESSAGE_SIZE=10485760   # 10 MB
  SMTP_MAX_MESSAGE_SIZE=52428800   # 50 MB
  SMTP_MAX_MESSAGE_SIZE=104857600  # 100 MB
  ```

#### SMTP_MAX_RECIPIENTS
- **Description:** Maximum recipients per message
- **Type:** Integer
- **Default:** `100`
- **Recommended:** 50-500
- **Examples:**
  ```bash
  SMTP_MAX_RECIPIENTS=100   # Default
  SMTP_MAX_RECIPIENTS=50    # Strict (anti-spam)
  SMTP_MAX_RECIPIENTS=500   # Mailing lists
  ```

---

### Rate Limiting

#### SMTP_RATE_LIMIT_PER_IP
- **Description:** Maximum messages per hour per IP address
- **Type:** Integer
- **Default:** `100`
- **Purpose:** Prevent spam and abuse from individual IPs
- **Examples:**
  ```bash
  SMTP_RATE_LIMIT_PER_IP=100   # Default
  SMTP_RATE_LIMIT_PER_IP=50    # Strict
  SMTP_RATE_LIMIT_PER_IP=1000  # High volume
  ```

#### SMTP_RATE_LIMIT_PER_USER
- **Description:** Maximum messages per hour per authenticated user
- **Type:** Integer
- **Default:** `200`
- **Purpose:** Separate rate limit for authenticated users (typically higher than IP limit)
- **Examples:**
  ```bash
  SMTP_RATE_LIMIT_PER_USER=200   # Default
  SMTP_RATE_LIMIT_PER_USER=100   # Strict
  SMTP_RATE_LIMIT_PER_USER=5000  # High volume authenticated users
  ```
- **Note:** This applies only to authenticated SMTP submissions. Unauthenticated connections still use IP-based limiting.

#### SMTP_RATE_LIMIT_CLEANUP_INTERVAL
- **Description:** How often (in seconds) to clean up old rate limit entries
- **Type:** Integer (seconds)
- **Default:** `3600` (1 hour)
- **Purpose:** Memory management for rate limiter hashmaps
- **Examples:**
  ```bash
  SMTP_RATE_LIMIT_CLEANUP_INTERVAL=3600  # Default - 1 hour
  SMTP_RATE_LIMIT_CLEANUP_INTERVAL=1800  # 30 minutes for high traffic
  SMTP_RATE_LIMIT_CLEANUP_INTERVAL=7200  # 2 hours for low traffic
  ```
- **Recommendation:** For high-traffic servers, use shorter intervals (30-60 minutes). For low-traffic servers, longer intervals (2-4 hours) are fine.

---

### Observability & Tracing

#### SMTP_ENABLE_TRACING
- **Description:** Enable OpenTelemetry distributed tracing
- **Type:** Boolean
- **Default:** `false`
- **Values:** `true`, `false`, `1`, `0`
- **Purpose:** Enable trace context propagation and span collection for distributed tracing
- **Examples:**
  ```bash
  SMTP_ENABLE_TRACING=true    # Enable tracing
  SMTP_ENABLE_TRACING=false   # Disable tracing (default)
  ```
- **Note:** When enabled, the server will create spans for SMTP operations and propagate trace context using W3C Trace Context standard.

#### SMTP_TRACING_SERVICE_NAME
- **Description:** Service name to identify this SMTP server in traces
- **Type:** String
- **Default:** `mail`
- **Purpose:** Helps identify this service in distributed tracing systems
- **Examples:**
  ```bash
  SMTP_TRACING_SERVICE_NAME=mail         # Default
  SMTP_TRACING_SERVICE_NAME=smtp-prod-us-west-1 # Production with region
  SMTP_TRACING_SERVICE_NAME=smtp-staging        # Staging environment
  ```
- **Recommendation:** Use descriptive names that include environment and region for easier debugging in production.

---

### Authentication

#### SMTP_ENABLE_AUTH
- **Description:** Enable SMTP authentication
- **Type:** Boolean
- **Default:** `true`
- **Values:** `true`, `false`, `1`, `0`
- **Examples:**
  ```bash
  SMTP_ENABLE_AUTH=true    # Enable (recommended)
  SMTP_ENABLE_AUTH=false   # Disable (open relay - DANGEROUS)
  ```

#### SMTP_DB_PATH
- **Description:** Path to SQLite database for user authentication
- **Type:** String (file path)
- **Default:** `./smtp.db`
- **Examples:**
  ```bash
  SMTP_DB_PATH=/var/lib/mail/smtp.db
  SMTP_DB_PATH=/data/smtp/users.db
  ```

---

### TLS Configuration

#### SMTP_ENABLE_TLS
- **Description:** Enable native STARTTLS support
- **Type:** Boolean
- **Default:** `false`
- **Note:** **Use TLS proxy instead** (see [TLS_PROXY_SETUP.md](./TLS_PROXY_SETUP.md))
- **Examples:**
  ```bash
  SMTP_ENABLE_TLS=false    # Recommended (use proxy)
  SMTP_ENABLE_TLS=true     # Experimental (cipher issues)
  ```

#### SMTP_TLS_CERT
- **Description:** Path to TLS certificate file
- **Type:** String (file path)
- **Required if:** `SMTP_ENABLE_TLS=true`
- **Format:** PEM
- **Examples:**
  ```bash
  SMTP_TLS_CERT=/etc/ssl/certs/mail.example.com.crt
  SMTP_TLS_CERT=/opt/mail/certs/server.pem
  ```

#### SMTP_TLS_KEY
- **Description:** Path to TLS private key file
- **Type:** String (file path)
- **Required if:** `SMTP_ENABLE_TLS=true`
- **Format:** PEM
- **Examples:**
  ```bash
  SMTP_TLS_KEY=/etc/ssl/private/mail.example.com.key
  SMTP_TLS_KEY=/opt/mail/certs/server-key.pem
  ```

---

### Spam Prevention

#### SMTP_SPAM_FILTER
- **Description:** Content-based spam scoring for unauthenticated inbound mail.
  Combines the SPF/DKIM/DMARC verdicts with DNSBL listings, reverse-DNS (PTR)
  and HELO sanity, and message heuristics (missing/forged headers, shouty or
  obfuscated subjects, spam phrases, link farms, hidden HTML text, dangerous
  attachments) into a single score. Authenticated submissions are never scored.
- **Type:** Boolean
- **Default:** `true`
- **Disposition:**
  - score `>= SMTP_SPAM_JUNK_SCORE` → delivered to the recipient's **Junk** mailbox
  - score `>= SMTP_SPAM_REJECT_SCORE` → rejected at SMTP time (`550`)
  - otherwise → delivered to the inbox
- **Headers added:** `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` (lists the
  rules that fired, e.g. `DNSBL_LISTED,SPF_FAIL,NO_PTR`).

#### SMTP_SPAM_JUNK_SCORE / SMTP_SPAM_REJECT_SCORE
- **Description:** Score thresholds for the Junk and reject bands.
- **Type:** Float
- **Defaults:** `5` (junk), `12` (reject)
- **Tuning:** Lower the junk score to be more aggressive; raise the reject score
  if you are worried about bouncing misconfigured-but-legitimate senders. A
  single DNSBL listing scores ~6 (→ Junk, not rejected, on its own).

#### SMTP_JUNK_FOLDER
- **Description:** Maildir subfolder spam is delivered into (`mail/<user>/<folder>/`).
- **Type:** String
- **Default:** `Junk`

#### SMTP_ENABLE_DNSBL
- **Description:** Enable DNSBL/RBL checking of the connecting IP. When enabled,
  a listing contributes to the spam score (see `SMTP_SPAM_FILTER`); it only
  hard-rejects when `SMTP_DNSBL_REJECT=true`.
- **Type:** Boolean
- **Default:** `true`
- **Examples:**
  ```bash
  SMTP_ENABLE_DNSBL=true   # Check IPs against blocklists (feeds the spam score)
  SMTP_ENABLE_DNSBL=false  # Disable (slightly faster, weaker filtering)
  ```

**DNSBL Lists Used:**
- zen.spamhaus.org
- bl.spamcop.net
- b.barracudacentral.org
- dnsbl.sorbs.net

> Spamhaus error/blocked-resolver answers (`127.255.255.0/24`) are ignored, so a
> rate-limited resolver never falsely flags every sender.

#### SMTP_DNSBL_REJECT
- **Description:** Hard-reject (`554`) connections from DNSBL-listed IPs at RCPT
  time, before the message body is sent (saves bandwidth on botnet floods),
  instead of only scoring the message toward Junk. Requires `SMTP_ENABLE_DNSBL`.
- **Type:** Boolean
- **Default:** `false`
- **Note:** Off by default because a single rare false positive would bounce
  legitimate mail. Scoring (the default) sends such mail to Junk, which is
  recoverable.

#### SMTP_ENABLE_GREYLIST
- **Description:** Enable greylisting for spam prevention
- **Type:** Boolean
- **Default:** `false`
- **Purpose:** Temporarily reject unknown sender/recipient/IP triplets
- **Examples:**
  ```bash
  SMTP_ENABLE_GREYLIST=true   # Enable greylisting
  SMTP_ENABLE_GREYLIST=false  # Disable
  ```

**Greylist Parameters:**
- Initial delay: 5 minutes
- Retry window: 4 hours
- Auto-whitelist after: 36 days

---

### Webhook Integration

#### SMTP_WEBHOOK_URL
- **Description:** Webhook URL for message notifications
- **Type:** String (URL)
- **Protocols:** HTTP, HTTPS
- **Examples:**
  ```bash
  SMTP_WEBHOOK_URL=https://api.example.com/webhook
  SMTP_WEBHOOK_URL=http://localhost:3000/smtp-events
  ```

#### SMTP_WEBHOOK_ENABLED
- **Description:** Enable webhook notifications
- **Type:** Boolean
- **Default:** `false` (enabled if URL provided)
- **Examples:**
  ```bash
  SMTP_WEBHOOK_ENABLED=true
  SMTP_WEBHOOK_ENABLED=false
  ```

**Webhook Payload:**
```json
{
  "from": "sender@example.com",
  "recipients": ["recipient1@example.com", "recipient2@example.com"],
  "size": 12345,
  "timestamp": 1234567890,
  "remote_addr": "192.168.1.100"
}
```

---

### Multi-Domain Hosting

One mail server instance can host mailboxes for several unrelated domains, each
fully isolated. See **[MULTI_DOMAIN_HOSTING.md](MULTI_DOMAIN_HOSTING.md)** for the
complete guide.

#### SMTP_LOCAL_DOMAINS
- **Description:** Additional domains the server accepts and delivers **locally**
  (instead of relaying outbound). The server's own hostname/parent domain is
  always local; list every *other* hosted domain here.
- **Type:** String (comma-separated)
- **Default:** *(empty)*
- **Examples:**
  ```bash
  SMTP_LOCAL_DOMAINS=example.com
  SMTP_LOCAL_DOMAINS=example.com,another-domain.org
  ```

**Isolated mailboxes:** a user whose `username` is a **full email address** (e.g.
`info@example.com`) gets its own maildir keyed by the full address
(`mail/info@example.com/`), so `info@example.com` and `info@other.com` are
distinct accounts. A user whose `username` is a bare local-part (e.g. `chris`)
keeps the legacy shared-namespace behaviour (`mail/chris/`, reachable as
`chris@any-hosted-domain`). The choice is per-user, made at account creation.

---

### Outbound DKIM Signing

Outbound mail is RSA-SHA256 (relaxed/relaxed) DKIM-signed. With multiple hosted
domains, each signs with its **own** key so the `d=` aligns with the `From:`
domain and DMARC passes on DKIM (not only SPF).

#### DKIM_DOMAIN / DKIM_SELECTOR / DKIM_PRIVATE_KEY_PATH
- **Description:** The **primary** DKIM signer. Also the fallback signer for any
  sender domain that has no dedicated key.
- **Type:** String / String / Path (PEM, PKCS#1 or PKCS#8 RSA private key)
- **Publish:** the public key at `<selector>._domainkey.<domain>` TXT as
  `v=DKIM1; k=rsa; p=<base64 SPKI>`.
- **Examples:**
  ```bash
  DKIM_DOMAIN=example.com
  DKIM_SELECTOR=mail
  DKIM_PRIVATE_KEY_PATH=/opt/mail/dkim/mail.private
  ```

#### DKIM_EXTRA_KEYS
- **Description:** Additional per-domain DKIM signers for other hosted domains.
  Each registers a signer selected at send time by the envelope sender's domain.
- **Type:** String — comma-separated `domain:selector:/path/to/key.pem` entries
- **Default:** *(empty)*
- **Examples:**
  ```bash
  DKIM_EXTRA_KEYS=example.com:mail:/opt/mail/dkim/example.private
  DKIM_EXTRA_KEYS=a.com:mail:/opt/mail/dkim/a.private,b.com:s1:/opt/mail/dkim/b.private
  ```

**Generate a domain key + DNS record:**
```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /opt/mail/dkim/example.private
# TXT value for  mail._domainkey.example.com :
echo "v=DKIM1; k=rsa; p=$(openssl rsa -in /opt/mail/dkim/example.private -pubout -outform DER 2>/dev/null | base64 -w0)"
```

---

## Configuration Files

### systemd Service with Environment File

**Create `/etc/mail/config`:**
```bash
# Server
SMTP_HOST=0.0.0.0
SMTP_PORT=2525
SMTP_HOSTNAME=mail.example.com
SMTP_MAX_CONNECTIONS=500

# Timeouts
SMTP_TIMEOUT_SECONDS=300
SMTP_DATA_TIMEOUT_SECONDS=600
SMTP_COMMAND_TIMEOUT_SECONDS=300
SMTP_GREETING_TIMEOUT_SECONDS=30

# Message Limits
SMTP_MAX_MESSAGE_SIZE=52428800
SMTP_MAX_RECIPIENTS=100

# Authentication
SMTP_ENABLE_AUTH=true
SMTP_DB_PATH=/var/lib/mail/smtp.db

# Spam Prevention
SMTP_ENABLE_DNSBL=true
SMTP_ENABLE_GREYLIST=true

# Webhook
SMTP_WEBHOOK_URL=https://api.example.com/webhook
SMTP_WEBHOOK_ENABLED=true

# Rate Limiting
SMTP_RATE_LIMIT_PER_IP=100
SMTP_RATE_LIMIT_PER_USER=200
SMTP_RATE_LIMIT_CLEANUP_INTERVAL=3600
```

**Create `/etc/systemd/system/mail.service`:**
```ini
[Unit]
Description=Mail Server
After=network.target

[Service]
Type=simple
User=smtp
Group=smtp
WorkingDirectory=/opt/mail
EnvironmentFile=/etc/mail/config
ExecStart=/opt/mail/mail
Restart=always
RestartSec=5

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/mail

[Install]
WantedBy=multi-user.target
```

---

## Configuration Profiles

### Development Profile

```bash
# .env.development
SMTP_HOST=127.0.0.1
SMTP_PORT=2525
SMTP_HOSTNAME=localhost
SMTP_MAX_CONNECTIONS=10
SMTP_ENABLE_AUTH=false
SMTP_ENABLE_DNSBL=false
SMTP_ENABLE_GREYLIST=false
SMTP_MAX_MESSAGE_SIZE=10485760
SMTP_TIMEOUT_SECONDS=600
```

### Staging Profile

```bash
# .env.staging
SMTP_HOST=0.0.0.0
SMTP_PORT=2525
SMTP_HOSTNAME=mail-staging.example.com
SMTP_MAX_CONNECTIONS=100
SMTP_ENABLE_AUTH=true
SMTP_DB_PATH=/var/lib/mail/staging.db
SMTP_ENABLE_DNSBL=false
SMTP_ENABLE_GREYLIST=false
SMTP_WEBHOOK_URL=https://staging-api.example.com/webhook
```

### Production Profile

```bash
# .env.production
SMTP_HOST=0.0.0.0
SMTP_PORT=2525
SMTP_HOSTNAME=mail.example.com
SMTP_MAX_CONNECTIONS=1000
SMTP_ENABLE_AUTH=true
SMTP_DB_PATH=/var/lib/mail/production.db
SMTP_ENABLE_DNSBL=true
SMTP_ENABLE_GREYLIST=true
SMTP_WEBHOOK_URL=https://api.example.com/webhook
SMTP_MAX_MESSAGE_SIZE=52428800
SMTP_MAX_RECIPIENTS=100
SMTP_RATE_LIMIT_PER_IP=100
SMTP_RATE_LIMIT_PER_USER=200
SMTP_RATE_LIMIT_CLEANUP_INTERVAL=3600
SMTP_TIMEOUT_SECONDS=300
SMTP_DATA_TIMEOUT_SECONDS=600
SMTP_COMMAND_TIMEOUT_SECONDS=300
SMTP_GREETING_TIMEOUT_SECONDS=30
```

---

## Docker Configuration

### docker-compose.yml

```yaml
version: '3.8'

services:
  mail:
    image: mail:latest
    container_name: mail
    restart: unless-stopped
    ports:
      - "2525:2525"
    environment:
      - SMTP_HOST=0.0.0.0
      - SMTP_PORT=2525
      - SMTP_HOSTNAME=mail.example.com
      - SMTP_MAX_CONNECTIONS=500
      - SMTP_ENABLE_AUTH=true
      - SMTP_DB_PATH=/data/smtp.db
      - SMTP_ENABLE_DNSBL=true
      - SMTP_ENABLE_GREYLIST=true
      - SMTP_WEBHOOK_URL=https://api.example.com/webhook
      - SMTP_MAX_MESSAGE_SIZE=52428800
      - SMTP_TIMEOUT_SECONDS=300
      - SMTP_DATA_TIMEOUT_SECONDS=600
    volumes:
      - ./data:/data
      - ./logs:/logs
    networks:
      - mail-network

networks:
  mail-network:
    driver: bridge
```

---

## Kubernetes Configuration

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: mail-config
  namespace: mail
data:
  SMTP_HOST: "0.0.0.0"
  SMTP_PORT: "2525"
  SMTP_HOSTNAME: "mail.example.com"
  SMTP_MAX_CONNECTIONS: "1000"
  SMTP_ENABLE_AUTH: "true"
  SMTP_DB_PATH: "/data/smtp.db"
  SMTP_ENABLE_DNSBL: "true"
  SMTP_ENABLE_GREYLIST: "true"
  SMTP_MAX_MESSAGE_SIZE: "52428800"
  SMTP_TIMEOUT_SECONDS: "300"
  SMTP_DATA_TIMEOUT_SECONDS: "600"
  SMTP_COMMAND_TIMEOUT_SECONDS: "300"
  SMTP_GREETING_TIMEOUT_SECONDS: "30"
```

### Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mail-secrets
  namespace: mail
type: Opaque
stringData:
  SMTP_WEBHOOK_URL: "https://api.example.com/webhook"
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mail
  namespace: mail
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mail
  template:
    metadata:
      labels:
        app: mail
    spec:
      containers:
      - name: mail
        image: mail:latest
        ports:
        - containerPort: 2525
        envFrom:
        - configMapRef:
            name: mail-config
        - secretRef:
            name: mail-secrets
        volumeMounts:
        - name: data
          mountPath: /data
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: mail-data
```

---

## Validation

### Check Configuration

```bash
# Print current configuration
./mail --help

# Test configuration
SMTP_PORT=2525 ./mail &
SERVER_PID=$!

# Test connection
telnet localhost 2525

# Cleanup
kill $SERVER_PID
```

### Verify Environment Variables

```bash
# List all SMTP environment variables
env | grep SMTP_

# Check specific setting
echo $SMTP_PORT
```

---

## Troubleshooting

### Configuration Not Applied

**Problem:** Changes not taking effect

**Solutions:**
1. Check environment variable syntax:
   ```bash
   # Correct
   SMTP_PORT=2525

   # Incorrect
   SMTP_PORT = 2525  # No spaces
   ```

2. Verify systemd service file:
   ```bash
   sudo systemctl cat mail.service
   ```

3. Restart service:
   ```bash
   sudo systemctl restart mail
   ```

### Port Already in Use

**Problem:** `Address already in use`

**Solutions:**
1. Check what's using the port:
   ```bash
   sudo lsof -i :2525
   ```

2. Use different port:
   ```bash
   SMTP_PORT=2526 ./mail
   ```

### Permission Denied

**Problem:** Cannot bind to privileged port (< 1024)

**Solutions:**
1. Use non-privileged port with proxy
2. Run as root (not recommended)
3. Use capabilities:
   ```bash
   sudo setcap 'cap_net_bind_service=+ep' ./mail
   ```

---

## Best Practices

1. **Use Environment Variables:** Easier to manage across environments
2. **Enable Authentication:** Prevent open relay abuse
3. **Use TLS Proxy:** More reliable than native STARTTLS
4. **Set Appropriate Timeouts:** Balance between usability and resource usage
5. **Enable DNSBL/Greylist:** Reduce spam (production only)
6. **Configure Webhooks:** Enable event notifications
7. **Set Rate Limits:** Prevent abuse
8. **Monitor Configuration:** Log configuration at startup

---

## Complete Configuration Reference

### Profile Comparison Table

| Setting | Development | Testing | Staging | Production | Type | Description |
|---------|------------|---------|---------|------------|------|-------------|
| **Server** |
| `smtp_port` | 2525 | 0 (random) | 25 | 25 | u16 | SMTP server port |
| `api_port` | 8081 | 0 (random) | 8080 | 8080 | u16 | API server port |
| `max_connections` | 100 | 10 | 500 | 2000 | u32 | Max concurrent connections |
| `connection_timeout_seconds` | 300 | 5 | 300 | 300 | u32 | Connection timeout |
| `command_timeout_seconds` | 60 | 2 | 60 | 60 | u32 | Command timeout |
| **Rate Limiting** |
| `rate_limit_window_seconds` | 60 | 60 | 60 | 60 | u32 | Rate limit window |
| `rate_limit_max_requests` | 1000 | 10000 | 500 | 200 | u32 | Max requests per window |
| `rate_limit_max_per_user` | 500 | 10000 | 200 | 100 | u32 | Max per authenticated user |
| **Message Limits** |
| `max_message_size` | 10 MB | 1 MB | 25 MB | 25 MB | usize | Maximum message size |
| `max_recipients` | 100 | 10 | 100 | 100 | u32 | Max recipients per message |
| **Storage** |
| `queue_batch_size` | 10 | 5 | 50 | 100 | usize | Queue batch size |
| `queue_flush_interval_ms` | 1000 | 100 | 2000 | 5000 | u64 | Queue flush interval |
| `database_pool_size` | 5 | 2 | 10 | 20 | u32 | Database connection pool |
| **Logging** |
| `log_level` | debug | warn | info | info | enum | Logging level |
| `enable_json_logging` | false | false | true | true | bool | JSON structured logs |
| `log_file_path` | null | null | /var/log/smtp | /var/log/smtp | ?[]u8 | Log file path |
| **Security** |
| `require_tls` | false | false | true | true | bool | Require TLS encryption |
| `require_auth` | false | false | true | true | bool | Require authentication |
| `tls_min_version` | 1.2 | 1.2 | 1.2 | 1.3 | string | Minimum TLS version |
| **Performance** |
| `buffer_pool_size` | 50 | 10 | 200 | 500 | u32 | Buffer pool size |
| `enable_io_uring` | false | false | false | true | bool | Enable io_uring (Linux) |
| `worker_threads` | 2 | 1 | 4 | 8 | u32 | Worker thread count |
| **Features** |
| `enable_spam_filter` | true | false | true | true | bool | Enable spam filtering |
| `enable_virus_scan` | false | false | true | true | bool | Enable virus scanning |
| `enable_greylist` | false | false | true | true | bool | Enable greylisting |
| `enable_webhooks` | true | false | true | true | bool | Enable webhook notifications |
| `enable_metrics` | true | false | true | true | bool | Enable metrics collection |
| `enable_tracing` | true | false | true | true | bool | Enable distributed tracing |
| **Resilience** |
| `circuit_breaker_threshold` | 10 | 3 | 5 | 10 | u32 | Circuit breaker threshold |
| `circuit_breaker_timeout_seconds` | 10 | 1 | 30 | 60 | u32 | Circuit breaker timeout |
| `max_retry_attempts` | 2 | 1 | 3 | 5 | u32 | Max retry attempts |
| `retry_delay_seconds` | 1 | 0 | 5 | 10 | u32 | Delay between retries |

### Environment Variable Override Reference

All profile settings can be overridden via environment variables. Use the `SMTP_` prefix with UPPER_SNAKE_CASE:

```bash
# Override any profile setting
SMTP_PROFILE=production \
SMTP_MAX_CONNECTIONS=5000 \
SMTP_WORKER_THREADS=16 \
SMTP_LOG_LEVEL=debug \
./mail
```

**Common Environment Variables:**

| Environment Variable | Profile Setting | Example |
|---------------------|-----------------|---------|
| `SMTP_PROFILE` | Profile selection | `production`, `dev`, `test` |
| `SMTP_PORT` | `smtp_port` | `2525`, `25`, `587` |
| `SMTP_HOST` | Server bind address | `0.0.0.0`, `127.0.0.1` |
| `SMTP_MAX_CONNECTIONS` | `max_connections` | `1000`, `2000` |
| `SMTP_LOG_LEVEL` | `log_level` | `debug`, `info`, `warn`, `error` |
| `SMTP_DB_PATH` | Database file path | `/var/lib/smtp/smtp.db` |
| `SMTP_ENABLE_TLS` | `require_tls` | `true`, `false` |
| `SMTP_ENABLE_AUTH` | `require_auth` | `true`, `false` |
| `SMTP_WORKER_THREADS` | `worker_threads` | `4`, `8`, `16` |
| `SMTP_MAX_MESSAGE_SIZE` | `max_message_size` | `10485760` (10MB) |
| `SMTP_ENABLE_GREYLIST` | `enable_greylist` | `true`, `false` |
| `SMTP_WEBHOOK_URL` | Webhook endpoint | `https://api.example.com/hook` |

### Tuning Recommendations

#### Small Deployment (< 1000 messages/hour)
```bash
SMTP_PROFILE=development \
SMTP_MAX_CONNECTIONS=100 \
SMTP_WORKER_THREADS=2 \
SMTP_DATABASE_POOL_SIZE=5
```

#### Medium Deployment (1000-10000 messages/hour)
```bash
SMTP_PROFILE=staging \
SMTP_MAX_CONNECTIONS=500 \
SMTP_WORKER_THREADS=4 \
SMTP_DATABASE_POOL_SIZE=10 \
SMTP_BUFFER_POOL_SIZE=200
```

#### Large Deployment (> 10000 messages/hour)
```bash
SMTP_PROFILE=production \
SMTP_MAX_CONNECTIONS=2000 \
SMTP_WORKER_THREADS=16 \
SMTP_DATABASE_POOL_SIZE=30 \
SMTP_BUFFER_POOL_SIZE=1000 \
SMTP_ENABLE_IO_URING=true
```

#### High Security (Banking, Healthcare)
```bash
SMTP_PROFILE=production \
SMTP_REQUIRE_TLS=true \
SMTP_REQUIRE_AUTH=true \
SMTP_TLS_MIN_VERSION=1.3 \
SMTP_ENABLE_SPAM_FILTER=true \
SMTP_ENABLE_VIRUS_SCAN=true \
SMTP_ENABLE_GREYLIST=true \
SMTP_RATE_LIMIT_MAX_REQUESTS=50 \
SMTP_MAX_MESSAGE_SIZE=5242880  # 5MB limit
```

---

## See Also

- [Configuration Profiles Source](../src/core/config_profiles.zig) - Complete profile definitions
- [TLS Proxy Setup](./TLS_PROXY_SETUP.md) - TLS termination proxy configuration
- [Thread Safety Audit](./THREAD_SAFETY_AUDIT.md) - Concurrency safety documentation
- [Database Schema](./DATABASE.md) - Database configuration and maintenance
- [Troubleshooting Guide](./TROUBLESHOOTING.md) - Configuration troubleshooting
- [Known Issues](./KNOWN_ISSUES_AND_SOLUTIONS.md) - Known configuration issues
- [Deployment Guide](./DEPLOYMENT.md) - Production deployment patterns

---

**Last Updated:** 2025-10-24
**Version:** v0.28.0
