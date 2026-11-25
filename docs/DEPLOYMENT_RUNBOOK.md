# Mail Server Deployment Runbook

**Version:** v0.28.0
**Date:** 2025-10-24

## Overview

This runbook provides step-by-step procedures for deploying, upgrading, and maintaining the Mail Server in production environments.

## Native Mail staging on AWS

Use a public Route 53 zone dedicated to the staging mailbox domain. For example, `mail.staging.example.com` is the server hostname and `staging.example.com` is the zone and mailbox domain. Delegate the zone from its authoritative parent and verify that a public NS lookup returns the Route 53 nameservers before creating the stack. The stack manages only the staging hostname's A record. Staging supports delivery between its own mailboxes. Its security group limits internet egress to HTTP and HTTPS.

Build the chosen Linux x86-64 revision with `zig build -Dtarget=x86_64-linux-gnu -Doptimize=ReleaseFast` in `packages/zig` after installing the repository dependencies. Publish a gzip tar archive under `staging/` in the test artifact bucket. Use the built executable as `mail-server` and include `scripts/mail-health.py`, `scripts/mail-health-watch.py`, `scripts/mail-sync-health.py`, and `scripts/setup-mail-health.sh` from the same revision at the archive root. Record the revision and SHA-256 of the archive.

Create `/mail-server/staging/provisioning-token` as an SSM SecureString in the target region with a 32-byte hex-encoded token. `/mail-server/staging/discord-webhook-url` is an optional SecureString for a staging alert receiver. The instance role can read those parameters and the selected artifact.

Run this from `packages/cloud` after setting `STAGING_DOMAIN_NAME` to the hostname, `STAGING_HOSTED_ZONE_ID` to the dedicated zone ID, `STAGING_ARTIFACT_S3_URI` to the published archive, and `STAGING_ARTIFACT_SHA256` to its checksum. `AWS_REGION` defaults to `us-east-1`.

```bash
bun run generate:staging > mail-staging.cfn.json
bun run deploy:staging
bun run status:staging
```

The deploy command validates the zone and creates `MailServerStagingStack`. An existing stack causes the command to fail. `bun run diff:staging` compares the current template with the deployed stack. After creation, connect via Session Manager and check `sudo cloud-init status --wait`, `sudo systemctl is-active mail`, and `sudo /usr/local/sbin/mail-protocol-health-check --deploy-gate`.

Verify the certificate and protocol endpoints on the staging hostname. Use port 587 for SMTP submission, 993 for IMAPS, 8443 for webmail, and 443 for EWS and ActiveSync. The provisioning listener uses loopback port 8099. Open a Session Manager port forwarding session for the synthetic signup and mailbox checks.

```bash
aws ssm start-session --target STAGING_INSTANCE_ID \
  --document-name AWS-StartPortForwardingSession \
  --parameters 'portNumber=8099,localPortNumber=8099'
```

With the tunnel open, run the deployed quota verifier from the Mail repository and supply the staging token in `MAIL_STAGING_PROVISIONING_TOKEN`. The TLS clients verify the staging hostname. The verifier allocates a fresh `qa-` mailbox prefix, checks exact storage and sending boundaries, and clears and suspends its synthetic mailboxes on exit. Keep the printed prefix with the deployment record.

```bash
python3 scripts/test-hosted-staging.py \
  --host mail.staging.example.com --domain staging.example.com \
  --provisioning-url http://127.0.0.1:8099
```

Use `--fixture /path/to/mail` to exercise the same client against a disposable TLS server. The verifier exercises SMTP submission, webmail, IMAP, EWS, ActiveSync, and private provisioning. The daemon restart, suspended SMTP retry, and UTC rollover tests continue to run in `scripts/test-hosted-limits.py --staging` with disposable daemon state.

For the local Stacks test process, set `MAIL_PROVISIONING_URL` to `http://127.0.0.1:8099`, `MAIL_PROVISIONING_TOKEN` to the staging token, `MAIL_FREE_SIGNUP_DOMAIN` to the staging mailbox domain, and `MAIL_WEBMAIL_ORIGIN` to the webmail URL from the stack output. Use a disposable signup database and configure the free-tier limits for the test. Record the deployed Mail, app, and SDK revisions and test results in #55, #57, and #61.

### Rehearse an additional hosted domain

Add each approved staging domain to `SMTP_LOCAL_DOMAINS`, then list it in
`SMTP_EXACT_MAILBOX_DOMAINS` and `SMTP_PROVISIONING_ADDITIONAL_DOMAINS`. These
settings take comma-separated domain names. Keep `SMTP_PROVISIONING_DOMAIN`
set to the primary domain and disable catch-all delivery. Restart Mail to
load the routing and provisioning settings.

Provision users with their full mailbox addresses. SMTP delivery and account
sign-in use the address's domain even when the same local part exists in
another domain. Create `postmaster@domain` through the operator CLI, since
the private provisioning API reserves that address. Check the additional
domain with the private `GET /provisioning/v1/domain?name=example.com`
endpoint before creating customer mailboxes. The daemon reports eligibility
from its configuration. Verify the account's DNS ownership claim in Stacks
before offering customer setup.

For team setup, the private `GET /provisioning/v1/team` takes the full
`mailbox` and provisioning `actor`. `POST /provisioning/v1/team` takes
those fields and the team `name`. The selected mailbox needs an active paid
service window on the additional domain. The first successful request
creates the team and appoints that mailbox as owner. Retries return the
existing team for the domain. The native domain rename moves that binding
with the mailbox addresses.

Run `python3 scripts/test-hosted-domains.py /path/to/mail` to exercise this
configuration with two disposable domains over native SMTP, IMAP, webmail,
EWS, and ActiveSync. Run `python3 scripts/test-hosted-cutover.py /path/to/mail`
to exercise local DNS MX changes, delivery through both cached routes, the
final IMAP delta, and recovery using a separate reverse checkpoint. Use a
public staging DNS zone to verify propagation and aligned authentication
before changing customer MX records.

### Inventory a hosted domain before transfer or retirement

Run the command from the daemon's working directory with the daemon's
configuration and `SMTP_DB_PATH`. Protect the output because it contains
mailbox and recovery addresses and sharing relationships.

```bash
umask 077
/opt/mail/mail-server domain inventory customer.example.com > native-inventory.json
```

The report reads one SQLite snapshot. It includes full mailbox addresses on
the exact domain, native assignment and operation IDs, access windows and
recovery settings, team membership and grants, forwards, and pending inbound
delivery. It identifies forwarding rules configured as Sieve so an operator
can review them before touching delivery. Local routing flags reflect the
configuration loaded by the command. Compare this with the Stacks billing
inventory to find reservations without a confirmed native result and mailbox
assignments without a matching billing record. Use both reports to plan the
transfer or retirement of the domain in #131.

### Retire the reviewed hosted mailboxes

Use the native operation ID issued by the Stacks billing lock and the exact
reviewed `domain inventory` file. Run against a daemon using the matching
Mail build and configuration. Drain pending delivery and resolve scheduled or
uncertain sends for those mailboxes before applying.

```bash
/opt/mail/mail-server domain retire native-operation-id native-inventory.json --yes
```

Mail verifies the current assignment roster and provisioning revisions, then
disables mailbox access and records the retirement as one SQLite transaction.
It preserves stored mail for operator recovery and reserves the retired
addresses. Keep the inventory file for retrying the same operation. Stacks can
read the receipt from the private `GET /provisioning/v1/retirement?id=…`
endpoint before releasing the billing seats and domain claim.

## Hosted mailbox diagnostics

Run the local report on the mailbox's Mail host. Use the daemon's working directory and database path. The staging stack uses `/var/lib/mail` for both.

```bash
cd /var/lib/mail
sudo -u mail-server env SMTP_DB_PATH=/var/lib/mail/smtp.db \
  /opt/mail/mail-server user:local hosted-status alice@staging.example.com
```

- Compare the observed enabled flag and byte quota with the requested values and recorded provisioning revision. If they differ, correlate the revision with the Stacks entitlement operation before making another provisioning change.
- For a full mailbox, check stored Maildir bytes, pending delivery reservations, and active file links. These share the byte budget. Moving messages to Trash keeps their bytes allocated.
- For a sending refusal, check recipients used today and the remaining allowance. The bucket uses UTC days. A counter dated in the future holds a metered allowance at zero. A legacy unlimited sending allowance appears as `recipients_remaining: null`.
- Pending, retry, and processing counts cover outbound queue rows attributed to this hosted mailbox. A suspended mailbox can still have queued deliveries. `outbound_queue: null` means the database has no hosted queue schema to inspect.

The report carries the observation time and an `audit_id`. Each successful report records `hosted.status` in `audit_log` with the effective operator UID and mailbox. The output is restricted to the mailbox identifier, operational state, and aggregate counters. Maildir and reservation counts may change while the daemon is delivering mail.

### Offboard a departed team owner

Use `mail team show` to confirm the departing owner and choose an existing
teammate. For a hosted team, the successor needs active paid service on the
team's domain. Run the handoff from the Mail host with the daemon's database.

```bash
/opt/mail/mail-server team offboard-owner studio alice@example.com bob@example.com operator-handoff-001
```

The handoff commits the replacement, membership removal, grant cleanup, and
`team.owner_handoff` audit entry together. Keep the operation ID with the ticket
and reuse it if the command's outcome is unclear. Confirm the successor can
manage the team, the departing mailbox has lost access to shared mail and
calendars, and outstanding invitations from the departing owner are gone.
Use the occupied-domain retirement workflow when the customer's mailbox itself
needs permanent retirement.

When a restore uses a snapshot from before an offboarding, repeat the recorded
command with its original operation ID on the restored database before opening
the listeners. Verify the successor's role and the former owner's shared
access on the restored host before returning it to service.

### Hosted service and export deadlines

The private v1 provisioning API accepts an optional `access_window` with
`service_until` and `read_until` as Unix seconds. Send the end of the verified
paid term plus grace as `service_until`, and the end of the export period as
`read_until`. The daemon applies both deadlines on access, including after
restart. It reports `full`, `read_only`, `expired`, or `disabled` for a
mailbox with a window. A missing window keeps the mailbox on its existing
operator-managed policy.

During export, SMTP temporarily defers new inbound mail, blocks outbound
submission, and holds queued outbound retries. Clients can read or download
existing data. After the export deadline SMTP refuses the recipient permanently
and authenticated access ends. An operator suspension takes precedence over
either deadline.

For renewals, post `mailbox`, `actor`, `operation_id`, the next `revision`, and
`access_window` to `/provisioning/v1/mailbox/access`. The SDK calls this
`applyAccess`. It changes the deadlines and revision while preserving the
account's enabled flag, storage quota, and sending allowance. An older
provisioning client that omits the window on an update preserves the deadlines.

## Local mailbox directory upgrade

Back up the Maildir and SQLite database together before upgrading a server with older ActiveSync clients. On startup, the server checks for full-address local accounts that still have mail under a short directory name such as `mail/alice`. It moves eligible messages to `mail/alice@example.com` before opening the protocol listeners. It also moves messages in a canonical custom folder's nested slots into the folder path exposed by IMAP and webmail. ActiveSync, IMAP, webmail, and EWS then read from the canonical mailbox. The upgrade retains existing message flags and client identifiers when it can reconcile both directories.

The startup log records the affected mailbox and any residual archive under `mail/.relocated-maildir-*`. If the short name has multiple owners, a folder layout conflicts, or a message filename already exists at the destination, both roots stay on disk and clients use the canonical root. Review the warning and establish ownership and file identity from the backup before resolving the conflict. When rolling back to a version that reads short-name directories, restore the matching pre-upgrade database and Maildir snapshot together.

---

## Table of Contents

1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Initial Deployment](#initial-deployment)
3. [Upgrade Procedures](#upgrade-procedures)
4. [Rollback Procedures](#rollback-procedures)
5. [Database Operations](#database-operations)
6. [TLS Certificate Management](#tls-certificate-management)
7. [Backup and Restore](#backup-and-restore)
8. [Monitoring Setup](#monitoring-setup)
9. [Performance Tuning](#performance-tuning)
10. [Incident Response](#incident-response)
11. [Maintenance Windows](#maintenance-windows)

---

## Pre-Deployment Checklist

### Infrastructure Requirements

- [ ] Server with minimum 2GB RAM, 2 CPU cores
- [ ] Persistent storage with minimum 20GB available
- [ ] Network connectivity (ports 25, 587, 8080, 8081)
- [ ] DNS records configured (MX, SPF, DKIM, DMARC)
- [ ] TLS certificates obtained (Let's Encrypt or commercial CA)
- [ ] Reverse proxy configured (nginx, Caddy, or HAProxy)

### Software Requirements

- [ ] Operating system: Linux (Ubuntu 22.04+ recommended)
- [ ] Zig 0.15.1 installed (for building from source)
- [ ] SQLite 3.35+ installed
- [ ] systemd for service management
- [ ] Prometheus (optional, for metrics)
- [ ] Log aggregation system (optional, for centralized logging)

### Security Requirements

- [ ] Firewall rules configured
- [ ] SELinux/AppArmor policies reviewed
- [ ] Service user account created (`smtp` user)
- [ ] File permissions set correctly (600 for database, 644 for binaries)
- [ ] Secrets management configured (environment variables or vault)

### Configuration Prepared

- [ ] Configuration profile selected (staging/production)
- [ ] Environment variables documented
- [ ] Database initialization plan
- [ ] Initial user accounts planned
- [ ] Filter rules prepared

---

## Initial Deployment

### Step 1: Build Application

```bash
# Clone repository
git clone https://github.com/yourusername/mail.git
cd mail

# Checkout stable version
git checkout v0.28.0

# Build release binary
zig build -Doptimize=ReleaseSafe

# Verify build
./zig-out/bin/mail --version
```

**Expected Output:**
```
Mail Server v0.28.0
Built with Zig 0.15.1
```

**Time:** ~5 minutes

---

### Step 2: Create Service User

```bash
# Create smtp user and group
sudo useradd -r -s /bin/false smtp

# Create directories
sudo mkdir -p /opt/mail
sudo mkdir -p /var/lib/mail
sudo mkdir -p /var/log/mail
sudo mkdir -p /etc/mail

# Set ownership
sudo chown -R smtp:smtp /var/lib/mail
sudo chown -R smtp:smtp /var/log/mail
sudo chown -R smtp:smtp /etc/mail
```

**Time:** 2 minutes

---

### Step 3: Install Application

```bash
# Copy binary
sudo cp ./zig-out/bin/mail /opt/mail/
sudo cp ./zig-out/bin/user-cli /opt/mail/

# Set permissions
sudo chown root:smtp /opt/mail/mail
sudo chmod 750 /opt/mail/mail

# Verify installation
/opt/mail/mail --version
```

**Time:** 1 minute

---

### Step 4: Configure Application

```bash
# Create configuration file
sudo tee /etc/mail/config.env << 'EOF'
# Mail Server Configuration - Production
SMTP_PROFILE=production

# Server Settings
SMTP_HOST=0.0.0.0
SMTP_PORT=2525
SMTP_HOSTNAME=mail.example.com
SMTP_MAX_CONNECTIONS=2000

# Timeouts
SMTP_TIMEOUT_SECONDS=300
SMTP_DATA_TIMEOUT_SECONDS=600
SMTP_COMMAND_TIMEOUT_SECONDS=300
SMTP_GREETING_TIMEOUT_SECONDS=30

# Message Limits
SMTP_MAX_MESSAGE_SIZE=26214400
SMTP_MAX_RECIPIENTS=100

# Authentication
SMTP_ENABLE_AUTH=true
SMTP_DB_PATH=/var/lib/mail/smtp.db

# Security
SMTP_ENABLE_TLS=false
SMTP_REQUIRE_TLS=false

# Spam Prevention
SMTP_ENABLE_DNSBL=true
SMTP_ENABLE_GREYLIST=true

# Rate Limiting
SMTP_RATE_LIMIT_PER_IP=200
SMTP_RATE_LIMIT_PER_USER=100
SMTP_RATE_LIMIT_CLEANUP_INTERVAL=3600

# Logging
SMTP_ENABLE_JSON_LOGGING=true

# Tracing
SMTP_ENABLE_TRACING=true
SMTP_TRACING_SERVICE_NAME=smtp-prod-us-east-1

# Webhooks (optional)
# SMTP_WEBHOOK_URL=https://api.example.com/webhook
# SMTP_WEBHOOK_ENABLED=true
EOF

# Secure configuration file
sudo chown root:smtp /etc/mail/config.env
sudo chmod 640 /etc/mail/config.env
```

**Time:** 3 minutes

---

### Step 5: Initialize Database

```bash
# Set database path
export SMTP_DB_PATH=/var/lib/mail/smtp.db

# Initialize database (migrations run automatically on first start)
# Create initial admin user
sudo -u smtp /opt/mail/user-cli create \
  admin@example.com \
  --password "$(openssl rand -base64 32)" \
  --email admin@example.com

# Verify database
sudo -u smtp sqlite3 $SMTP_DB_PATH "SELECT username, enabled FROM users;"
```

**Expected Output:**
```
admin@example.com|1
```

**Time:** 2 minutes

---

### Step 6: Configure systemd Service

```bash
# Create systemd service unit
sudo tee /etc/systemd/system/mail.service << 'EOF'
[Unit]
Description=Mail Server
Documentation=https://github.com/yourusername/mail
After=network.target

[Service]
Type=simple
User=smtp
Group=smtp
WorkingDirectory=/opt/mail
EnvironmentFile=/etc/mail/config.env
ExecStart=/opt/mail/mail
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/mail /var/log/mail
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Resource limits
LimitNOFILE=65536
LimitNPROC=512

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
sudo systemctl daemon-reload
```

**Time:** 2 minutes

---

### Step 7: Configure Reverse Proxy (nginx)

```bash
# Install nginx if not present
sudo apt-get install -y nginx certbot python3-certbot-nginx

# Create nginx configuration
sudo tee /etc/nginx/sites-available/mail << 'EOF'
# Mail Server - TLS Termination Proxy

upstream smtp_backend {
    server localhost:2525 max_fails=3 fail_timeout=30s;
}

server {
    listen 25;
    listen 587;

    server_name mail.example.com;

    # TLS configuration
    ssl_certificate /etc/letsencrypt/live/mail.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mail.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Proxy to SMTP backend
    location / {
        proxy_pass http://smtp_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts for SMTP
        proxy_connect_timeout 60s;
        proxy_send_timeout 600s;
        proxy_read_timeout 600s;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/mail /etc/nginx/sites-enabled/mail

# Test configuration
sudo nginx -t

# Reload nginx
sudo systemctl reload nginx
```

**Time:** 5 minutes

---

### Step 8: Obtain TLS Certificates

```bash
# Obtain Let's Encrypt certificate
sudo certbot --nginx -d mail.example.com

# Verify certificate
sudo certbot certificates

# Setup auto-renewal
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer
```

**Time:** 3 minutes

---

### Step 9: Start Service

```bash
# Validate configuration
sudo -u smtp SMTP_PROFILE=production /opt/mail/mail --validate-only

# Start service
sudo systemctl start mail

# Check status
sudo systemctl status mail

# Enable auto-start on boot
sudo systemctl enable mail

# View logs
sudo journalctl -u mail -f
```

**Expected Log Output:**
```json
{"timestamp":1698765432,"level":"INFO","service":"mail","hostname":"prod-smtp-01","message":"=== Mail Server Starting ==="}
{"timestamp":1698765432,"level":"INFO","service":"mail","hostname":"prod-smtp-01","message":"Configuration loaded and validated successfully:"}
{"timestamp":1698765432,"level":"INFO","service":"mail","hostname":"prod-smtp-01","message":"Mail Server listening on 0.0.0.0:2525"}
```

**Time:** 3 minutes

---

### Step 10: Verify Deployment

```bash
# Check health endpoint
curl -s http://localhost:8081/health | jq .

# Check metrics endpoint
curl -s http://localhost:8081/metrics | head -20

# Test SMTP connection
telnet localhost 25
# Expected: 220 mail.example.com ESMTP Service Ready
# Type: QUIT

# Send test email
echo "Subject: Test Email

This is a test message." | sendmail -f test@example.com recipient@example.com

# Check logs for successful delivery
sudo journalctl -u mail | grep "Message received"
```

**Time:** 5 minutes

**Total Deployment Time:** ~31 minutes

---

## Upgrade Procedures

### Standard Upgrade (Rolling Update)

**Pre-requisites:**
- [ ] New version tested in staging environment
- [ ] Backup completed
- [ ] Maintenance window scheduled (optional for rolling update)
- [ ] Rollback plan prepared

### Step 1: Pre-Upgrade Checks

```bash
# Check current version
/opt/mail/mail --version

# Check service health
curl -s http://localhost:8081/health | jq .status

# Record current metrics
curl -s http://localhost:8081/stats > /tmp/pre-upgrade-stats.json

# Backup database
sudo -u smtp sqlite3 /var/lib/mail/smtp.db ".backup /var/lib/mail/smtp-backup-$(date +%Y%m%d-%H%M%S).db"

# Verify backup
sudo -u smtp sqlite3 /var/lib/mail/smtp-backup-*.db "PRAGMA integrity_check;"
```

**Time:** 3 minutes

---

### Step 2: Build New Version

```bash
# Fetch new version
cd /tmp
git clone https://github.com/yourusername/mail.git mail-new
cd mail-new
git checkout v0.29.0

# Build
zig build -Doptimize=ReleaseSafe

# Verify build
./zig-out/bin/mail --version
# Expected: Mail Server v0.29.0
```

**Time:** 5 minutes

---

### Step 3: Deploy New Binary

After stopping Mail and its other writers, capture and verify the complete
recovery point before installing the new executable. Include both databases,
Maildir, and the matching configuration using the [backup procedure](#backup-and-restore).

```bash
# Stop service
sudo systemctl stop mail

# Capture and verify the complete recovery point here.

# Backup old binary
sudo cp /opt/mail/mail /opt/mail/mail.v0.28.0

# Install new binary
sudo cp /tmp/mail-new/zig-out/bin/mail /opt/mail/
sudo chown root:smtp /opt/mail/mail
sudo chmod 750 /opt/mail/mail

# Validate new version
/opt/mail/mail --version

# Test configuration
sudo -u smtp SMTP_PROFILE=production /opt/mail/mail --validate-only
```

**Time:** 2 minutes

---

### Step 4: Start and Verify

```bash
# Start service
sudo systemctl start mail

# Monitor startup
sudo journalctl -u mail -f -n 50

# Wait 30 seconds for warm-up
sleep 30

# Check health
curl -s http://localhost:8081/health | jq .

# Verify version
curl -s http://localhost:8081/stats | jq .

# Test SMTP connection
echo "QUIT" | telnet localhost 25
```

**Time:** 3 minutes

---

### Step 5: Post-Upgrade Validation

```bash
# Compare metrics (should be similar)
curl -s http://localhost:8081/stats > /tmp/post-upgrade-stats.json
diff /tmp/pre-upgrade-stats.json /tmp/post-upgrade-stats.json

# Send test message
echo "Subject: Post-Upgrade Test

Upgrade to v0.29.0 successful" | sendmail test@example.com

# Monitor for errors
sudo journalctl -u mail --since "5 minutes ago" | grep -i error

# Check database migrations
sudo -u smtp sqlite3 /var/lib/mail/smtp.db "SELECT version, name FROM schema_migrations ORDER BY version DESC LIMIT 5;"
```

**Time:** 3 minutes

**Total Upgrade Time:** ~16 minutes

---

## Rollback Procedures

### When to Rollback

- Critical bugs discovered in new version
- Performance degradation > 20%
- Database corruption detected
- Service health degraded/unhealthy

### Rollback Steps

1. Pause intake or allow the upstream relay to queue mail. Stop Mail and any
   other writers, then capture a new recovery point with both databases,
   Maildir, and the matching configuration. Keep the pre-upgrade checkpoint
   and the current recovery point available throughout the rollback.
2. Reopen the current data with the previous executable on an isolated copy.
   Verify the readers and workers you intend to run, including every pending
   Outbox format. A binary-only rollback keeps the data together. Pause any
   listener or worker whose compatibility remains unproven.
3. For a checkpoint rollback, restore the matching pre-upgrade databases,
   Maildir, and configuration together into a separate directory. Review the
   messages, drafts, DAV changes, and send receipts accepted since that
   checkpoint before reopening intake. Use the saved current recovery point
   and the candidate binary to recover those writes, reconciling delivery
   receipts before retrying sends.
4. Verify healthy listeners, real inbound delivery, IMAP UID and UIDVALIDITY,
   a draft, and representative DAV resources before resuming the affected
   services. Keep both recovery points through the verification window.

### Preserve two-step verification during rollback

The current Mail database enforces two-step verification when a browser session
is created. During a binary-only rollback on that database, previously verified
sessions still work. A previous binary without the current verifier rejects new
sign-ins and Combined inbox links for enrolled mailboxes. Unenrolled webmail
and mail protocol access remain available. Restore the current binary to resume
interactive sign-in for enrolled mailboxes.

A database checkpoint may predate an enrollment or the consumption of a
recovery code. Run the restored daemon with `SMTP_ENABLE_WEBMAIL=false`. In
that temporary configuration, unset `SMTP_HOSTED_SIGN_IN_ORIGIN`,
`SMTP_WEBMAIL_MFA_KEY`, and `SMTP_WEBMAIL_OPERATOR_ID` if set. Keep a protected
copy of the normal configuration and key. Reconcile the current factor state
using the saved recovery point and the current verifier before reopening webmail.

Rehearse a binary-only rollback with a pre-MFA candidate that already supports
hosted sign-in and Combined inbox. The fixture enrolls a disposable mailbox,
checks all three session paths on the older binary, delivers SMTP mail and reads
it over IMAP, then rolls forward and spends a recovery code once.

```bash
python3 scripts/test-webmail-mfa.py /path/to/candidate --previous /path/to/previous-mail
```

### Rehearse a published-version rollback

Use the published executable for the version being replaced. Verify the
download against its release manifest and run this fixture on an isolated
host with throwaway accounts. The v0.3.26 rehearsal ran on Ubuntu 24.04 arm64.

```bash
python3 scripts/test-mail-release-upgrade.py /path/to/candidate --previous /path/to/released-mail
```

The fixture upgrades real mail, draft, and DAV data. For verified legacy DAV
collections, apply the [offline ownership assignment](../WEBMAIL.md#upgrading-persisted-dav-data).
Keep DAV paused when temporarily running v0.3.26 over a store that has those
assignments. Its mail worker is exercised against a simple compatible queued
send. The fixture then rolls the full store forward and checks the writes
from both versions, followed by a domain rename and a separate checkpoint
restore.

---

## Database Operations

### Backup Database

```bash
# Online backup (preferred)
sudo -u smtp sqlite3 /var/lib/mail/smtp.db ".backup /var/lib/mail/smtp-backup-$(date +%Y%m%d).db"

# Compress backup
sudo gzip /var/lib/mail/smtp-backup-*.db

# Copy to remote backup location
scp /var/lib/mail/smtp-backup-*.db.gz backup-server:/backups/smtp/
```

**Frequency:** Daily (automated via cron)

---

### Restore Database

```bash
# Stop service
sudo systemctl stop mail

# Restore backup
sudo -u smtp gunzip < /var/lib/mail/smtp-backup-20251024.db.gz > /var/lib/mail/smtp.db

# Verify integrity
sudo -u smtp sqlite3 /var/lib/mail/smtp.db "PRAGMA integrity_check;"

# Start service
sudo systemctl start mail
```

---

### Database Maintenance

```bash
# Vacuum database (monthly)
sudo -u smtp sqlite3 /var/lib/mail/smtp.db "VACUUM;"

# Update statistics
sudo -u smtp sqlite3 /var/lib/mail/smtp.db "ANALYZE;"

# Check integrity
sudo -u smtp sqlite3 /var/lib/mail/smtp.db "PRAGMA integrity_check;"

# Clean old queue entries
sudo -u smtp sqlite3 /var/lib/mail/smtp.db "DELETE FROM message_queue WHERE created_at < strftime('%s', 'now', '-30 days');"
```

---

## TLS Certificate Management

### Certificate Renewal (Let's Encrypt)

```bash
# Manual renewal (certbot handles auto-renewal)
sudo certbot renew

# Reload nginx after renewal
sudo systemctl reload nginx

# Verify certificate
openssl s_client -connect mail.example.com:25 -starttls smtp < /dev/null | grep "Verify return code"
# Expected: Verify return code: 0 (ok)
```

**Frequency:** Automatic (certbot timer runs twice daily)

---

### Certificate Monitoring

```bash
# Check expiry date
sudo certbot certificates

# Alert if < 30 days until expiry
EXPIRY=$(sudo openssl x509 -enddate -noout -in /etc/letsencrypt/live/mail.example.com/fullchain.pem | cut -d= -f2)
echo "Certificate expires: $EXPIRY"
```

---

## Backup and Restore

See the [authenticated Restic backup and recovery procedure](ENCRYPTION_AT_REST.md#backup-operations) for a full-service restore that includes Maildir and preserves verified message links.

### Full Backup Script

```bash
#!/bin/bash
# /opt/mail/scripts/backup.sh

BACKUP_DIR="/var/backups/mail"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RETENTION_DAYS=30

mkdir -p $BACKUP_DIR

# Backup database
sudo -u smtp sqlite3 /var/lib/mail/smtp.db ".backup $BACKUP_DIR/smtp-$TIMESTAMP.db"

# Backup configuration
sudo cp /etc/mail/config.env $BACKUP_DIR/config-$TIMESTAMP.env

# Compress
gzip $BACKUP_DIR/smtp-$TIMESTAMP.db

# Remove old backups
find $BACKUP_DIR -name "*.gz" -mtime +$RETENTION_DAYS -delete

# Verify latest backup
gunzip -t $BACKUP_DIR/smtp-$TIMESTAMP.db.gz && echo "Backup successful"

# Copy to remote location (optional)
# rsync -az $BACKUP_DIR/ backup-server:/backups/smtp/
```

**Setup:**
```bash
# Create cron job for daily backups at 2 AM
echo "0 2 * * * /opt/mail/scripts/backup.sh" | sudo crontab -
```

---

## Monitoring Setup

### Prometheus Configuration

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: 'mail'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:8081']
        labels:
          environment: 'production'
          service: 'mail'
```

### Grafana Dashboard

Import dashboard ID: (create custom dashboard with metrics from `/metrics`)

**Key Metrics to Monitor:**
- `smtp_connections_active` - Active connections
- `smtp_messages_received_total` - Message throughput
- `smtp_messages_rejected_total` - Rejection rate
- `smtp_auth_failures_total` - Authentication failures
- `smtp_rate_limit_hits_total` - Rate limiting

---

### Alerting Rules (Prometheus)

```yaml
# /etc/prometheus/rules/mail.yml
groups:
  - name: smtp_server_alerts
    interval: 30s
    rules:
      - alert: SMTPServerDown
        expr: up{job="mail"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Mail Server is down"
          description: "Mail Server {{ $labels.instance }} has been down for more than 1 minute"

      - alert: HighConnectionUsage
        expr: smtp_connections_active / smtp_max_connections > 0.8
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High connection usage"
          description: "Mail Server is using {{ $value }}% of max connections"

      - alert: HighRejectionRate
        expr: rate(smtp_messages_rejected_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High message rejection rate"
          description: "Rejection rate is {{ $value }} messages/sec"

      - alert: AuthenticationFailures
        expr: rate(smtp_auth_failures_total[5m]) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate"
          description: "Auth failure rate is {{ $value }} failures/sec (possible brute force attack)"
```

---

## Performance Tuning

### Connection Tuning

```bash
# For high-volume servers (5000+ messages/hour)
SMTP_MAX_CONNECTIONS=5000
SMTP_WORKER_THREADS=16
SMTP_DATABASE_POOL_SIZE=30
SMTP_BUFFER_POOL_SIZE=1000
```

### Kernel Tuning (Linux)

```bash
# /etc/sysctl.d/99-mail.conf
# Increase connection limits
net.core.somaxconn=4096
net.ipv4.tcp_max_syn_backlog=4096
net.ipv4.ip_local_port_range=10000 65535

# Enable TCP Fast Open
net.ipv4.tcp_fastopen=3

# Apply settings
sudo sysctl -p /etc/sysctl.d/99-mail.conf
```

---

## Incident Response

### Service Outage Response

1. **Detect:** Monitor alerts, health checks failing
2. **Assess:** Check service status, logs, metrics
3. **Communicate:** Notify stakeholders
4. **Investigate:** Review logs, metrics, recent changes
5. **Resolve:** Apply fix or rollback
6. **Verify:** Confirm service restoration
7. **Document:** Post-mortem report

### Common Issues and Solutions

**Issue: High Memory Usage**
```bash
# Check memory usage
ps aux | grep mail

# Restart service if OOM risk
sudo systemctl restart mail

# Adjust configuration
SMTP_MAX_CONNECTIONS=1000  # Reduce
SMTP_DATABASE_POOL_SIZE=10  # Reduce
```

**Issue: Database Locked**
```bash
# Check for long-running queries
sudo -u smtp sqlite3 /var/lib/mail/smtp.db "PRAGMA busy_timeout=10000;"

# Restart service
sudo systemctl restart mail
```

**Outbound queue and delivery alerts**

The watchdog checks free space on the runtime filesystem, the Maildir filesystem,
and the filesystem containing the configured `SMTP_DB_PATH`. It follows symlinks
and checks each filesystem once. It reports an unavailable path as a failed check.
The runtime defaults to `/opt/mail` and the Maildir to `/opt/mail/mail`. For a
different layout, set `--storage-path` and `--mailbox-path` when invoking
`mail-health-watch.py`. The runtime keeps a capacity check when the mailboxes and
database use a separate volume.

On hosts with the Mail health timer installed, the watchdog reads the SMTP
database configured by `SMTP_DB_PATH` in `/etc/mail/mail.env`. It raises an
incident when queued outbound deliveries in pending, processing, or retry
state exceed 1,000. A separate incident fires when terminal failures exceed
5% of completed outbound queue recipients in the current and previous 14 UTC
minute buckets. A recipient enters the denominator when the queue records
delivery or a terminal failure.

The watchdog sends incident and recovery notifications through its persisted
Discord outbox. A database read failure retains any active incident and
reports the monitoring failure. A slow notification receiver leaves SMTP
processing independent of alert delivery.

**Hosted operations and backup alerts**

Set `MAIL_OPERATIONS_TOKEN` in the Stacks app and add the same dedicated
credential to the root-managed Mail environment file. Set
`MAIL_APP_OPERATIONS_URL` there to the Stacks HTTPS origin followed by
`/api/operations/health`. The watchdog rejects redirects and stale reports.
The operator endpoint includes aggregate counts. Webmail health and alerts
use only fixed check labels and outcomes. The monitor retains active hosted
incidents while it cannot fetch a fresh report.

Hosted provisioning alerts on an unavailable private listener or a free or
paid mailbox still awaiting confirmation after 15 minutes. Billing alerts on
unprocessed signed webhook events older than 15 minutes, an absent or stale
reconciliation run, and mailbox access-update failures that persist for 15
minutes. Keep the Stacks billing scheduler running every five minutes.

When the Restic backup timer is installed, the watchdog checks the timestamp in
`/var/lib/mail-storage/data/restic/last-success`. A missing, invalid, future,
or more than 25-hour-old success marker opens an incident. Set
`MAIL_RESTIC_STATUS_FILE` in the Mail environment file when the configured
backup writes its success marker elsewhere. The marker is written after
Restic verifies the off-host backup.

**Authenticated client sync alerts**

Create a dedicated mailbox, such as `sync-canary@staging.example.com`, and
leave its Inbox empty. Create the `Mail-Health` calendar and
`Mail-Health-Contacts` address book for that mailbox using authenticated
`MKCALENDAR` and `MKCOL` requests on `/calendars/<mailbox>/Mail-Health/` and
`/addressbooks/<mailbox>/Mail-Health-Contacts/`. Keep the canary separate from customer
mailboxes and routes. Save the canary configuration to a root-owned file with
mode 0600 and put its path in `MAIL_SYNC_HEALTH_CONFIG` in the Mail
environment file.

```json
{
  "mailbox": "sync-canary@staging.example.com",
  "password": "<canary mailbox password>",
  "canary_id": "<32 lowercase hex characters from openssl rand -hex 16>",
  "imaps_port": 993,
  "dav_port": 443,
  "protocols": ["imap", "caldav", "carddav", "activesync", "ews"]
}
```

Set the ports to the actual local TLS listeners. A private CA can be
specified with `ca_file`. The monitor verifies the host certificate. It
appends one synthetic message over IMAPS, verifies its UID and reads the
new item using an ActiveSync SyncKey and EWS SyncState. The CalDAV and
CardDAV checks verify creation and deletion through successive sync
tokens. The monitor removes its own synthetic items and reports a failure
when the Inbox contains unrelated mail or a probe path holds unexpected
data. ActiveSync and EWS checks use IMAPS as the canary message writer.
Only the selected protocol checks appear in the status report. Probe
traffic, credentials and returned item identifiers stay out of alerts.

The EWS canary starts with an empty Inbox and consumes the state from its
first item. Same-size replacement tracking is covered by
[the separate EWS sync issue](https://github.com/mail-os/mail/issues/133).

Run `python3 scripts/test-mail-sync-health.py /path/to/mail` for the
disposable native rehearsal. On staging, confirm a clean result with the
configured timer, induce a failure in the canary, and record the incident
and recovery at the staging receiver in #71.

```bash
systemctl status mail-health.timer
journalctl -u mail-health.service -n 30 --no-pager
sudo cat /var/lib/mail-health/public/status.json
```

---

## Maintenance Windows

### Scheduled Maintenance Template

**Pre-Maintenance (T-24 hours):**
- [ ] Notify users of maintenance window
- [ ] Complete full backup
- [ ] Test changes in staging
- [ ] Prepare rollback plan

**During Maintenance:**
- [ ] Set service to maintenance mode (reject with 421)
- [ ] Complete changes (upgrade, config, etc.)
- [ ] Validate changes
- [ ] Remove maintenance mode

**Post-Maintenance:**
- [ ] Monitor for 1 hour
- [ ] Notify users of completion
- [ ] Document changes

---

## See Also

- [Configuration Guide](./CONFIGURATION.md)
- [Troubleshooting Guide](./TROUBLESHOOTING.md)
- [API Reference](./API_REFERENCE.md)
- [Database Documentation](./DATABASE.md)

---

**Last Updated:** 2025-10-24
**Version:** v0.28.0
