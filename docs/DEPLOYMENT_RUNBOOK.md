# Mail Server Deployment Runbook

**Version:** v0.28.0
**Date:** 2025-10-24

## Overview

This runbook provides step-by-step procedures for deploying, upgrading, and maintaining the Mail Server in production environments.

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

```bash
# Stop service
sudo systemctl stop mail

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

```bash
# Step 1: Stop current service
sudo systemctl stop mail

# Step 2: Restore old binary
sudo cp /opt/mail/mail.v0.28.0 /opt/mail/mail

# Step 3: Rollback database (if migrations ran)
sudo -u smtp cp /var/lib/mail/smtp-backup-*.db /var/lib/mail/smtp.db

# Step 4: Verify configuration
sudo -u smtp /opt/mail/mail --validate-only

# Step 5: Start service
sudo systemctl start mail

# Step 6: Verify health
curl -s http://localhost:8081/health | jq .status
# Expected: "healthy"

# Step 7: Monitor logs
sudo journalctl -u mail -f
```

**Rollback Time:** ~5 minutes

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

**Issue: Queue Backup**
```bash
# Check queue size
curl -s http://localhost:8080/api/queue | jq .queue_size

# Process queue manually if needed
# (Queue processor runs automatically)
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
