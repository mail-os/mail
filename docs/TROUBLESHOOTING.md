# Troubleshooting Guide

Comprehensive troubleshooting guide for diagnosing and resolving common issues with the SMTP server.

## Table of Contents

1. [General Troubleshooting Steps](#general-troubleshooting-steps)
2. [Service Not Starting](#service-not-starting)
3. [Connection Issues](#connection-issues)
4. [Authentication Problems](#authentication-problems)
5. [Email Delivery Issues](#email-delivery-issues)
6. [TLS/SSL Problems](#tlsssl-problems)
7. [Performance Issues](#performance-issues)
8. [Database Issues](#database-issues)
9. [Storage Problems](#storage-problems)
10. [Queue Issues](#queue-issues)
11. [Memory and Resource Issues](#memory-and-resource-issues)
12. [Monitoring and Logging](#monitoring-and-logging)
13. [Docker and Container Issues](#docker-and-container-issues)
14. [Kubernetes Issues](#kubernetes-issues)
15. [Security and Firewall](#security-and-firewall)
16. [Advanced Diagnostics](#advanced-diagnostics)

---

## General Troubleshooting Steps

### 1. Check Service Status

```bash
# Systemd
sudo systemctl status mail

# View recent logs
sudo journalctl -u mail -n 100 --no-pager

# Follow logs in real-time
sudo journalctl -u mail -f

# Docker
docker ps | grep mail
docker logs mail

# Kubernetes
kubectl get pods -n smtp-system
kubectl logs -l app=mail -n smtp-system --tail=100
```

### 2. Verify Configuration

```bash
# Check environment file
cat /etc/smtp/smtp.env

# Validate syntax (no trailing spaces, proper formatting)
grep -n "^[^#=]*=" /etc/smtp/smtp.env

# Check file permissions
ls -la /etc/smtp/smtp.env
# Expected: -rw------- (600) smtp:smtp
```

### 3. Test Connectivity

```bash
# Check if ports are listening
sudo ss -tlnp | grep -E "(25|587|465|8080|9090)"

# Test SMTP connection
telnet localhost 25
# Expected: 220 <hostname> ESMTP

# Test with OpenSSL (for TLS)
openssl s_client -connect localhost:587 -starttls smtp
openssl s_client -connect localhost:465

# Check health endpoint
curl http://localhost:8080/health
# Expected: {"status":"healthy",...}
```

### 4. Review Logs

**Log Locations:**
- Systemd: `journalctl -u mail`
- File: `/var/lib/smtp/logs/smtp.log`
- Docker: `docker logs mail`
- Kubernetes: `kubectl logs <pod-name> -n smtp-system`

**Common Log Patterns:**

```bash
# Authentication failures
grep "Authentication failed" /var/lib/smtp/logs/smtp.log

# Connection errors
grep -i "error" /var/lib/smtp/logs/smtp.log | tail -20

# Rate limit hits
grep "Rate limit exceeded" /var/lib/smtp/logs/smtp.log

# Database errors
grep -i "database" /var/lib/smtp/logs/smtp.log
```

---

## Service Not Starting

### Issue: Port Already in Use

**Symptoms:**
```
Error: Address already in use (os error 48)
Failed to bind to 0.0.0.0:25
```

**Diagnosis:**
```bash
# Find what's using the port
sudo lsof -i :25
sudo ss -tlnp | grep :25

# Common culprits: postfix, sendmail, exim
```

**Solution:**
```bash
# Stop conflicting service
sudo systemctl stop postfix
sudo systemctl disable postfix

# Or change SMTP server port
# Edit /etc/smtp/smtp.env
SMTP_PORT=2525

sudo systemctl restart mail
```

### Issue: Permission Denied on Port 25

**Symptoms:**
```
Error: Permission denied (os error 13)
Failed to bind to 0.0.0.0:25
```

**Diagnosis:**
Ports below 1024 require root privileges or special capabilities.

**Solution:**

**Option 1: Use systemd socket activation** (Recommended)
```bash
# Create socket unit
sudo tee /etc/systemd/system/mail.socket << 'EOF'
[Unit]
Description=Mail Server Socket
Before=mail.service

[Socket]
ListenStream=25
ListenStream=587
ListenStream=465
Accept=no

[Install]
WantedBy=sockets.target
EOF

# Update service to use socket
sudo systemctl enable mail.socket
sudo systemctl start mail.socket
```

**Option 2: Grant CAP_NET_BIND_SERVICE capability**
```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/mail

# Verify
getcap /usr/local/bin/mail
# Expected: /usr/local/bin/mail cap_net_bind_service=ep
```

**Option 3: Use port forwarding**
```bash
# Redirect port 25 to unprivileged port
sudo iptables -t nat -A PREROUTING -p tcp --dport 25 -j REDIRECT --to-port 2525

# Update configuration
SMTP_PORT=2525
```

### Issue: Missing Dependencies

**Symptoms:**
```
Error: sqlite3: no version information available
Error while loading shared libraries: libsqlite3.so.0
```

**Solution:**
```bash
# Ubuntu/Debian
sudo apt-get install -y libsqlite3-0 libssl3

# RHEL/CentOS
sudo dnf install -y sqlite-libs openssl-libs

# Verify installation
ldd /usr/local/bin/mail
```

### Issue: Configuration File Not Found

**Symptoms:**
```
Warning: Could not load configuration file
Using default configuration
```

**Solution:**
```bash
# Create configuration file
sudo mkdir -p /etc/smtp
sudo cp /path/to/smtp.env.example /etc/smtp/smtp.env

# Set proper permissions
sudo chown smtp:smtp /etc/smtp/smtp.env
sudo chmod 600 /etc/smtp/smtp.env

# Verify systemd EnvironmentFile path
grep EnvironmentFile /etc/systemd/system/mail.service
```

### Issue: Database Initialization Failed

**Symptoms:**
```
Error: unable to open database file
Error: attempt to write a readonly database
```

**Solution:**
```bash
# Check database directory permissions
ls -la /var/lib/smtp/
sudo chown -R smtp:smtp /var/lib/smtp

# Initialize database manually
sudo -u smtp /usr/local/bin/user-cli init

# Check database file permissions
ls -la /var/lib/smtp/smtp.db
# Should be owned by smtp:smtp with 644 permissions
```

---

## Connection Issues

### Issue: Connection Refused

**Symptoms:**
- `telnet: Unable to connect to remote host: Connection refused`
- Clients cannot connect to SMTP server

**Diagnosis:**
```bash
# Check if service is running
sudo systemctl status mail

# Check if port is listening
sudo ss -tlnp | grep :25

# Check firewall rules
sudo iptables -L -n | grep 25
sudo ufw status | grep 25
```

**Solution:**
```bash
# Start service if stopped
sudo systemctl start mail

# Open firewall ports
sudo ufw allow 25/tcp
sudo ufw allow 587/tcp
sudo ufw allow 465/tcp

# Or for firewalld
sudo firewall-cmd --permanent --add-service=smtp
sudo firewall-cmd --permanent --add-service=smtp-submission
sudo firewall-cmd --reload
```

### Issue: Connection Timeout

**Symptoms:**
- Connections hang and eventually timeout
- No response from server

**Diagnosis:**
```bash
# Test from external host
telnet your-server-ip 25

# Check network path
traceroute your-server-ip
mtr your-server-ip

# Check for rate limiting
grep "Rate limit" /var/lib/smtp/logs/smtp.log

# Check max connections
curl http://localhost:8080/stats | jq '.active_connections'
```

**Solution:**
```bash
# Increase connection timeout
# Edit /etc/smtp/smtp.env
CONNECTION_TIMEOUT=300  # 5 minutes

# Increase max connections
MAX_CONNECTIONS=2000

# Check cloud provider security groups (AWS, GCP, Azure)
# Ensure inbound rules allow ports 25, 587, 465

# Restart service
sudo systemctl restart mail
```

### Issue: Too Many Connections

**Symptoms:**
```
421 Too many connections, please try again later
Error: connection limit reached
```

**Diagnosis:**
```bash
# Check current connections
sudo ss -tn | grep :25 | wc -l

# Check max connections setting
grep MAX_CONNECTIONS /etc/smtp/smtp.env

# Check system limits
ulimit -n
cat /proc/sys/fs/file-max
```

**Solution:**
```bash
# Increase max connections
# Edit /etc/smtp/smtp.env
MAX_CONNECTIONS=5000

# Increase system file descriptor limit
sudo tee -a /etc/security/limits.conf << 'EOF'
smtp soft nofile 65536
smtp hard nofile 65536
EOF

# Increase systemd service limits
sudo mkdir -p /etc/systemd/system/mail.service.d
sudo tee /etc/systemd/system/mail.service.d/limits.conf << 'EOF'
[Service]
LimitNOFILE=65536
EOF

sudo systemctl daemon-reload
sudo systemctl restart mail
```

### Issue: Connection Drops During Transfer

**Symptoms:**
- Connection closes unexpectedly during message transfer
- `421 Connection timeout`

**Diagnosis:**
```bash
# Check for network issues
ping -c 10 your-server-ip

# Check system resources
top
free -h
df -h

# Review logs for errors
journalctl -u mail | grep -i "timeout\|disconnect"
```

**Solution:**
```bash
# Increase transfer timeout
CONNECTION_TIMEOUT=600  # 10 minutes

# Check TCP keepalive settings
sudo sysctl net.ipv4.tcp_keepalive_time
sudo sysctl net.ipv4.tcp_keepalive_probes
sudo sysctl net.ipv4.tcp_keepalive_intvl

# Adjust if needed
sudo tee -a /etc/sysctl.d/99-smtp.conf << 'EOF'
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
EOF

sudo sysctl -p /etc/sysctl.d/99-smtp.conf
```

---

## Authentication Problems

### Issue: Authentication Always Fails

**Symptoms:**
```
535 Authentication failed
Invalid username or password
```

**Diagnosis:**
```bash
# Check if user exists
sudo -u smtp /usr/local/bin/user-cli list

# Check database
sudo sqlite3 /var/lib/smtp/smtp.db "SELECT username, email FROM users;"

# Check authentication in logs
grep "Authentication" /var/lib/smtp/logs/smtp.log | tail -20
```

**Solution:**
```bash
# Reset user password
sudo -u smtp /usr/local/bin/user-cli reset username@example.com

# Verify user is active
sudo sqlite3 /var/lib/smtp/smtp.db \
  "SELECT username, is_active FROM users WHERE username='username@example.com';"

# Test authentication manually
openssl s_client -connect localhost:587 -starttls smtp
# Enter:
# AUTH PLAIN <base64(username\0username\0password)>
```

### Issue: Authentication Not Offered

**Symptoms:**
- EHLO response doesn't include `250-AUTH PLAIN LOGIN`
- `503 Authentication not enabled`

**Diagnosis:**
```bash
# Check if AUTH is enabled
grep SMTP_ENABLE_AUTH /etc/smtp/smtp.env

# Test EHLO response
telnet localhost 587
# Type: EHLO test.example.com
```

**Solution:**
```bash
# Enable authentication
# Edit /etc/smtp/smtp.env
SMTP_ENABLE_AUTH=true

sudo systemctl restart mail

# Verify AUTH is advertised
echo "EHLO test.example.com" | nc localhost 587
```

### Issue: Database Connection Failed

**Symptoms:**
```
Error: unable to open database
Authentication temporarily unavailable
```

**Diagnosis:**
```bash
# Check database file exists
ls -la /var/lib/smtp/smtp.db

# Check database integrity
sudo sqlite3 /var/lib/smtp/smtp.db "PRAGMA integrity_check;"

# Check permissions
ls -la /var/lib/smtp/smtp.db
```

**Solution:**
```bash
# Fix permissions
sudo chown smtp:smtp /var/lib/smtp/smtp.db
sudo chmod 644 /var/lib/smtp/smtp.db

# Rebuild database if corrupted
sudo -u smtp mv /var/lib/smtp/smtp.db /var/lib/smtp/smtp.db.backup
sudo -u smtp /usr/local/bin/user-cli init

# Restore users (if needed)
# Manual restore from backup or recreate users
```

### Issue: Constant-Time Comparison Timeout

**Symptoms:**
```
Authentication taking too long
Connection timeout during AUTH
```

**Diagnosis:**
```bash
# Check Argon2id parameters
grep -E "time_cost|memory_cost|parallelism" src/auth.zig

# Monitor authentication time
journalctl -u mail | grep "Authentication" | tail -20
```

**Solution:**
```bash
# Reduce Argon2id parameters (less secure but faster)
# Requires recompilation with adjusted parameters
# Default: time_cost=3, memory=64MB, parallelism=4
# Faster: time_cost=2, memory=32MB, parallelism=2

# Or upgrade server hardware (more CPU cores)
```

---

## Email Delivery Issues

### Issue: Messages Stuck in Queue

**Symptoms:**
- Queue size keeps growing
- Messages not being delivered
- `QUEUE_SIZE` metric increasing

**Diagnosis:**
```bash
# Check queue size
ls -la /var/lib/smtp/queue/ | wc -l

# Check queue stats via API
curl http://localhost:8080/api/queue/stats

# Check for errors in logs
grep -i "delivery\|queue" /var/lib/smtp/logs/smtp.log | tail -50
```

**Solution:**
```bash
# Check network connectivity to destination servers
dig MX gmail.com
telnet gmail-smtp-in.l.google.com 25

# Check DNS resolution
host example.com

# Manually retry queue
# (if queue retry CLI is implemented)
# sudo -u smtp queue-cli retry --all

# Check for rate limiting by destination
grep "rate limit\|throttle" /var/lib/smtp/logs/smtp.log

# Increase retry attempts
# Edit configuration (if available)
MAX_RETRY_ATTEMPTS=10
RETRY_INTERVAL=300  # 5 minutes
```

### Issue: All Messages Bouncing

**Symptoms:**
- Every message generates a bounce
- 550 errors in logs

**Diagnosis:**
```bash
# Check bounce messages
grep "bounce\|550" /var/lib/smtp/logs/smtp.log

# Check SPF/DKIM/DMARC status
grep -E "SPF|DKIM|DMARC" /var/lib/smtp/logs/smtp.log

# Check if server is blacklisted
dig +short 2.0.0.127.zen.spamhaus.org
# If returns result, IP is blacklisted
```

**Solution:**
```bash
# Configure reverse DNS (PTR record)
# Contact your ISP or hosting provider

# Set up SPF record
# Add to DNS: "v=spf1 ip4:your-server-ip -all"

# Configure DKIM signing
# Generate DKIM keys and add DNS record

# Request delisting from blacklists
# Visit: spamhaus.org, spamcop.net, etc.

# Verify MX records
dig MX yourdomain.com
```

### Issue: Relay Access Denied

**Symptoms:**
```
554 Relay access denied
Not authorized to relay through this server
```

**Diagnosis:**
```bash
# Check relay configuration
grep RELAY /etc/smtp/smtp.env

# Check authentication
# Relaying usually requires authentication
```

**Solution:**
```bash
# Require authentication for relaying
SMTP_REQUIRE_AUTH_FOR_RELAY=true

# Or configure allowed relay domains
RELAY_ALLOWED_DOMAINS=example.com,example.net

# Or configure relay by IP
RELAY_ALLOWED_IPS=10.0.0.0/8,192.168.0.0/16

sudo systemctl restart mail
```

### Issue: Messages Delayed

**Symptoms:**
- Messages take hours to deliver
- Greylisting causing delays

**Diagnosis:**
```bash
# Check greylist status
grep "greylist" /var/lib/smtp/logs/smtp.log

# Check retry schedule
curl http://localhost:8080/api/queue/stats
```

**Solution:**
```bash
# Disable greylisting (not recommended)
SMTP_ENABLE_GREYLIST=false

# Or reduce greylist delay
GREYLIST_DELAY=60  # 1 minute instead of default 5

# Whitelist known senders
# Add to greylist whitelist database
sudo sqlite3 /var/lib/smtp/smtp.db \
  "INSERT INTO greylist_whitelist (ip) VALUES ('203.0.113.0/24');"

sudo systemctl restart mail
```

---

## TLS/SSL Problems

### Issue: TLS Handshake Failed

**Symptoms:**
```
Error: TLS handshake failed
SSL_ERROR_SYSCALL
unable to verify the first certificate
```

**Diagnosis:**
```bash
# Test TLS connection
openssl s_client -connect localhost:587 -starttls smtp -showcerts

# Check certificate validity
openssl x509 -in /etc/smtp/certs/server.crt -text -noout

# Check certificate expiration
openssl x509 -in /etc/smtp/certs/server.crt -noout -enddate

# Verify certificate chain
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt /etc/smtp/certs/server.crt
```

**Solution:**
```bash
# Renew expired certificate
sudo certbot renew

# Fix certificate permissions
sudo chown smtp:smtp /etc/smtp/certs/server.crt /etc/smtp/certs/server.key
sudo chmod 644 /etc/smtp/certs/server.crt
sudo chmod 600 /etc/smtp/certs/server.key

# Use full certificate chain
# Ensure server.crt contains both cert and intermediate CA
cat server.crt intermediate.crt > fullchain.crt
```

### Issue: Certificate Not Trusted

**Symptoms:**
- Clients report "certificate not trusted"
- Self-signed certificate warnings

**Diagnosis:**
```bash
# Check certificate issuer
openssl x509 -in /etc/smtp/certs/server.crt -noout -issuer

# Check if self-signed
openssl x509 -in /etc/smtp/certs/server.crt -noout -issuer -subject
```

**Solution:**
```bash
# Option 1: Get certificate from trusted CA (Let's Encrypt)
sudo certbot certonly --standalone -d mail.example.com

# Update paths
TLS_CERT_PATH=/etc/letsencrypt/live/mail.example.com/fullchain.pem
TLS_KEY_PATH=/etc/letsencrypt/live/mail.example.com/privkey.pem

# Option 2: Add self-signed cert to clients
# Export and install certificate on client machines

# Option 3: Use reverse proxy with proper cert
# nginx or HAProxy with Let's Encrypt certificate
```

### Issue: STARTTLS Not Working

**Symptoms:**
- `454 TLS not available`
- STARTTLS command fails

**Diagnosis:**
```bash
# Check if TLS is enabled
grep TLS_MODE /etc/smtp/smtp.env

# Check certificate files exist
ls -la /etc/smtp/certs/server.{crt,key}

# Test STARTTLS
openssl s_client -connect localhost:587 -starttls smtp
```

**Solution:**
```bash
# Enable TLS
TLS_MODE=STARTTLS
TLS_CERT_PATH=/etc/smtp/certs/server.crt
TLS_KEY_PATH=/etc/smtp/certs/server.key

# Generate certificate if missing
sudo openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout /etc/smtp/certs/server.key \
  -out /etc/smtp/certs/server.crt \
  -days 365 -subj "/CN=mail.example.com"

sudo chown smtp:smtp /etc/smtp/certs/server.{crt,key}
sudo chmod 600 /etc/smtp/certs/server.key

sudo systemctl restart mail
```

### Issue: Cipher Mismatch

**Symptoms:**
```
Error: no shared cipher
SSL handshake failed: no suitable cipher
```

**Diagnosis:**
```bash
# Check supported ciphers
openssl s_client -connect localhost:587 -starttls smtp -cipher 'ALL:COMPLEMENTOFALL'

# Check client cipher requirements
# Different clients support different cipher suites
```

**Solution:**
```bash
# Update to modern TLS library (zig-tls)
# Or use reverse proxy with proven TLS stack

# nginx TLS configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256...';
ssl_prefer_server_ciphers off;

# HAProxy TLS configuration
ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384
ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11
```

---

## Performance Issues

### Issue: High CPU Usage

**Symptoms:**
- CPU usage consistently > 80%
- Server becoming unresponsive
- Slow email processing

**Diagnosis:**
```bash
# Check CPU usage
top -b -n 1 | grep mail
ps aux | grep mail

# Profile application
# (if profiling is enabled in debug build)

# Check for infinite loops in logs
journalctl -u mail | grep -i "loop\|hang"

# Check connection count
sudo ss -tn | grep :25 | wc -l
```

**Solution:**
```bash
# Limit max connections
MAX_CONNECTIONS=500

# Enable connection timeout
CONNECTION_TIMEOUT=120  # 2 minutes

# Enable rate limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=30

# Increase worker threads (if applicable)
WORKER_THREADS=8  # Match CPU core count

# Use CPU affinity
sudo systemctl edit mail
# Add: CPUAffinity=0-7

sudo systemctl daemon-reload
sudo systemctl restart mail
```

### Issue: High Memory Usage

**Symptoms:**
- Memory usage keeps growing
- Server crashes with OOM
- Swap usage increasing

**Diagnosis:**
```bash
# Check memory usage
free -h
ps aux | grep mail | awk '{print $6}'

# Check for memory leaks
# Run with debug build and memory profiler

# Check message queue size
ls /var/lib/smtp/queue/ | wc -l

# Check buffer sizes
grep -E "BUFFER|CACHE" /etc/smtp/smtp.env
```

**Solution:**
```bash
# Set memory limits
sudo systemctl edit mail
# Add:
# [Service]
# MemoryMax=2G
# MemoryHigh=1.5G

# Reduce cache sizes
CACHE_SIZE=536870912  # 512MB instead of 1GB

# Reduce max message size
SMTP_MAX_MESSAGE_SIZE=10485760  # 10MB

# Enable aggressive memory reclaim
# Restart service periodically (not ideal)
sudo systemctl restart mail

# Or implement memory pooling (code change required)
```

### Issue: Slow Email Processing

**Symptoms:**
- Messages take minutes to process
- High latency in metrics
- Queue backup

**Diagnosis:**
```bash
# Check metrics
curl http://localhost:8080/metrics | grep processing_time

# Check I/O wait
iostat -x 1 10

# Check disk performance
sudo hdparm -tT /dev/sda

# Check database performance
time sqlite3 /var/lib/smtp/smtp.db "SELECT COUNT(*) FROM messages;"
```

**Solution:**
```bash
# Enable database WAL mode
sudo -u smtp sqlite3 /var/lib/smtp/smtp.db "PRAGMA journal_mode=WAL;"

# Move queue to faster storage (SSD/NVMe)
sudo mkdir -p /mnt/fast-storage/queue
sudo mv /var/lib/smtp/queue/* /mnt/fast-storage/queue/
sudo ln -sf /mnt/fast-storage/queue /var/lib/smtp/queue

# Disable spam/virus scanning for testing
SPAM_CHECK_ENABLED=false
VIRUS_SCAN_ENABLED=false

# Increase I/O priority
sudo systemctl edit mail
# Add: IOSchedulingClass=realtime

# Tune kernel I/O
sudo tee -a /etc/sysctl.d/99-smtp-io.conf << 'EOF'
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
vm.swappiness = 10
EOF
sudo sysctl -p /etc/sysctl.d/99-smtp-io.conf
```

### Issue: Database Lock Contention

**Symptoms:**
```
Error: database is locked
SQLITE_BUSY error
```

**Diagnosis:**
```bash
# Check database mode
sudo sqlite3 /var/lib/smtp/smtp.db "PRAGMA journal_mode;"

# Check for long-running queries
# Enable SQLite logging if available

# Check concurrent connections
lsof /var/lib/smtp/smtp.db
```

**Solution:**
```bash
# Enable WAL mode (highly recommended)
sudo -u smtp sqlite3 /var/lib/smtp/smtp.db "PRAGMA journal_mode=WAL;"

# Increase busy timeout
# (requires code change in database initialization)
# PRAGMA busy_timeout = 5000;  -- 5 seconds

# Consider migrating to PostgreSQL
# Follow PostgreSQL setup in DEPLOYMENT.md

# Reduce concurrent database operations
# Implement connection pooling (code change)
```

---

## Database Issues

### Issue: Database Corrupted

**Symptoms:**
```
Error: database disk image is malformed
SQLITE_CORRUPT error
```

**Diagnosis:**
```bash
# Check database integrity
sudo sqlite3 /var/lib/smtp/smtp.db "PRAGMA integrity_check;"

# Check file system
sudo fsck /dev/sda1
```

**Solution:**
```bash
# Stop service
sudo systemctl stop mail

# Backup corrupted database
sudo cp /var/lib/smtp/smtp.db /var/lib/smtp/smtp.db.corrupted

# Attempt recovery with dump/restore
sudo sqlite3 /var/lib/smtp/smtp.db.corrupted .dump > dump.sql
sudo sqlite3 /var/lib/smtp/smtp.db.new < dump.sql

# If successful, replace database
sudo mv /var/lib/smtp/smtp.db.new /var/lib/smtp/smtp.db
sudo chown smtp:smtp /var/lib/smtp/smtp.db

# If recovery fails, restore from backup
sudo cp /var/backups/smtp/latest/smtp.db /var/lib/smtp/smtp.db

sudo systemctl start mail
```

### Issue: Database Growing Too Large

**Symptoms:**
- Database file several GB in size
- Slow queries
- Disk space issues

**Diagnosis:**
```bash
# Check database size
du -h /var/lib/smtp/smtp.db

# Check table sizes
sudo sqlite3 /var/lib/smtp/smtp.db << 'EOF'
SELECT
    name,
    SUM(pgsize) as size_bytes
FROM dbstat
GROUP BY name
ORDER BY size_bytes DESC;
EOF

# Check message count
sudo sqlite3 /var/lib/smtp/smtp.db "SELECT COUNT(*) FROM messages;"
```

**Solution:**
```bash
# Archive old messages
# (implement archival script or use GDPR deletion)
sudo sqlite3 /var/lib/smtp/smtp.db << 'EOF'
DELETE FROM messages
WHERE received_at < datetime('now', '-90 days');
EOF

# Vacuum database
sudo systemctl stop mail
sudo -u smtp sqlite3 /var/lib/smtp/smtp.db "VACUUM;"
sudo systemctl start mail

# Enable auto-vacuum
sudo sqlite3 /var/lib/smtp/smtp.db "PRAGMA auto_vacuum = FULL;"

# Or migrate to time-series storage
# Edit /etc/smtp/smtp.env
STORAGE_TYPE=timeseries
STORAGE_PATH=/var/lib/smtp/archive

sudo systemctl restart mail
```

### Issue: Foreign Key Constraint Failed

**Symptoms:**
```
Error: FOREIGN KEY constraint failed
Cannot delete user - related records exist
```

**Diagnosis:**
```bash
# Check foreign key constraints
sudo sqlite3 /var/lib/smtp/smtp.db << 'EOF'
PRAGMA foreign_keys;
PRAGMA foreign_key_check;
EOF

# Find related records
sudo sqlite3 /var/lib/smtp/smtp.db \
  "SELECT COUNT(*) FROM messages WHERE sender='user@example.com';"
```

**Solution:**
```bash
# Delete related records first
sudo sqlite3 /var/lib/smtp/smtp.db << 'EOF'
BEGIN TRANSACTION;
DELETE FROM messages WHERE sender='user@example.com';
DELETE FROM messages WHERE recipient='user@example.com';
DELETE FROM users WHERE email='user@example.com';
COMMIT;
EOF

# Or use GDPR deletion tool (handles cascading)
sudo -u smtp /usr/local/bin/gdpr-cli delete user@example.com
```

---

## Storage Problems

### Issue: Disk Full

**Symptoms:**
```
Error: No space left on device
Cannot write message to disk
```

**Diagnosis:**
```bash
# Check disk space
df -h

# Find largest directories
du -h --max-depth=1 /var/lib/smtp | sort -hr

# Check queue size
du -sh /var/lib/smtp/queue/

# Check log size
du -sh /var/lib/smtp/logs/
```

**Solution:**
```bash
# Clean old messages (if using Maildir/time-series)
find /var/lib/smtp/data -type f -mtime +90 -delete

# Truncate logs
sudo truncate -s 0 /var/lib/smtp/logs/smtp.log

# Enable log rotation
sudo tee /etc/logrotate.d/mail << 'EOF'
/var/lib/smtp/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 smtp smtp
    postrotate
        systemctl reload mail > /dev/null 2>&1 || true
    endscript
}
EOF

# Archive messages to S3
# Edit /etc/smtp/smtp.env
STORAGE_TYPE=s3
S3_BUCKET=smtp-archive
S3_REGION=us-east-1

# Expand disk
# (Cloud provider specific - resize volume)
# AWS: aws ec2 modify-volume --size 200 --volume-id vol-xxx
# Then: sudo resize2fs /dev/sda1
```

### Issue: Maildir Corruption

**Symptoms:**
```
Error: Cannot read message file
Invalid message format in Maildir
```

**Diagnosis:**
```bash
# Check Maildir structure
ls -la /var/lib/smtp/data/

# Validate Maildir format
# Each user should have: cur/ new/ tmp/
find /var/lib/smtp/data -type d -name "cur" -o -name "new" -o -name "tmp"

# Check for orphaned files
find /var/lib/smtp/data -type f ! -path "*/cur/*" ! -path "*/new/*" ! -path "*/tmp/*"
```

**Solution:**
```bash
# Recreate Maildir structure
for user_dir in /var/lib/smtp/data/*; do
    sudo mkdir -p "$user_dir"/{cur,new,tmp}
    sudo chown -R smtp:smtp "$user_dir"
    sudo chmod -R 755 "$user_dir"
done

# Move orphaned messages to new/
find /var/lib/smtp/data -type f ! -path "*/cur/*" ! -path "*/new/*" ! -path "*/tmp/*" \
    -exec sh -c 'mv "$1" "$(dirname "$1")/new/"' _ {} \;

# Validate message files
find /var/lib/smtp/data -name "*:2,*" -type f -exec file {} \; | grep -v "ASCII text"
```

### Issue: Permission Denied on Storage

**Symptoms:**
```
Error: Permission denied
Cannot create file in /var/lib/smtp/data
```

**Diagnosis:**
```bash
# Check ownership
ls -la /var/lib/smtp/

# Check permissions
find /var/lib/smtp -type d -ls
find /var/lib/smtp -type f -ls

# Check SELinux context (RHEL/CentOS)
ls -Z /var/lib/smtp/
```

**Solution:**
```bash
# Fix ownership
sudo chown -R smtp:smtp /var/lib/smtp

# Fix permissions
sudo find /var/lib/smtp -type d -exec chmod 755 {} \;
sudo find /var/lib/smtp -type f -exec chmod 644 {} \;
sudo chmod 600 /var/lib/smtp/smtp.db

# Fix SELinux context
sudo restorecon -Rv /var/lib/smtp

# Or temporarily disable SELinux (not recommended)
sudo setenforce 0
```

---

## Queue Issues

### Issue: Queue Not Processing

**Symptoms:**
- Messages accumulate in queue
- No delivery attempts in logs
- Queue worker not running

**Diagnosis:**
```bash
# Check queue size
ls /var/lib/smtp/queue/ | wc -l

# Check if queue processor is running
ps aux | grep queue

# Check logs for queue errors
grep -i "queue" /var/lib/smtp/logs/smtp.log | tail -50

# Check queue stats
curl http://localhost:8080/api/queue/stats
```

**Solution:**
```bash
# Check configuration
grep -i "queue" /etc/smtp/smtp.env

# Enable queue processing
QUEUE_ENABLED=true
QUEUE_WORKER_THREADS=4
QUEUE_BATCH_SIZE=100

# Restart service
sudo systemctl restart mail

# Manually trigger queue processing (if CLI available)
# sudo -u smtp queue-cli process

# Check for stuck messages
find /var/lib/smtp/queue -type f -mtime +1
```

### Issue: Queue Messages Have Wrong Permissions

**Symptoms:**
```
Error: cannot read queue file
Permission denied on queue message
```

**Diagnosis:**
```bash
# Check queue file permissions
ls -la /var/lib/smtp/queue/

# Check queue directory permissions
stat /var/lib/smtp/queue/
```

**Solution:**
```bash
# Fix permissions
sudo chown -R smtp:smtp /var/lib/smtp/queue
sudo chmod -R 755 /var/lib/smtp/queue
sudo find /var/lib/smtp/queue -type f -exec chmod 644 {} \;
```

### Issue: Duplicate Messages in Queue

**Symptoms:**
- Same message delivered multiple times
- Duplicate message IDs in queue

**Diagnosis:**
```bash
# Find duplicate message IDs
find /var/lib/smtp/queue -type f -exec basename {} \; | sort | uniq -d

# Check message headers
# Look for duplicate Message-ID headers
```

**Solution:**
```bash
# Remove duplicates (keep oldest)
find /var/lib/smtp/queue -type f -printf '%T+ %p\n' | \
    sort | \
    awk '{files[$2]++; if(files[$2]>1) print $2}' | \
    xargs rm

# Fix queue deduplication logic (code change required)
```

---

## Memory and Resource Issues

### Issue: Out of Memory (OOM)

**Symptoms:**
```
Error: cannot allocate memory
Killed (OOM killer)
Service exits unexpectedly
```

**Diagnosis:**
```bash
# Check OOM killer logs
dmesg | grep -i "out of memory\|oom"
journalctl -k | grep -i "oom"

# Check memory usage
free -h
ps aux | grep mail | awk '{print $6}'

# Check memory limits
systemctl show mail | grep Memory
```

**Solution:**
```bash
# Increase system memory (add RAM)

# Set memory limits to prevent OOM
sudo systemctl edit mail
# Add:
[Service]
MemoryMax=4G
MemoryHigh=3G
MemorySwapMax=0

# Reduce memory usage
MAX_CONNECTIONS=200  # Fewer connections
CACHE_SIZE=268435456  # 256MB cache
BUFFER_SIZE=8192  # 8KB buffers

# Enable swap (temporary)
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Monitor for memory leaks
# Use debug build with allocator tracking
```

### Issue: Too Many Open Files

**Symptoms:**
```
Error: Too many open files
socket: Too many open files
```

**Diagnosis:**
```bash
# Check current file descriptor usage
sudo ls -la /proc/$(pgrep mail)/fd | wc -l

# Check limits
ulimit -n
cat /proc/sys/fs/file-max

# Check service limits
systemctl show mail | grep LimitNOFILE
```

**Solution:**
```bash
# Increase system-wide limit
sudo tee -a /etc/sysctl.d/99-smtp.conf << 'EOF'
fs.file-max = 200000
EOF
sudo sysctl -p /etc/sysctl.d/99-smtp.conf

# Increase user limits
sudo tee -a /etc/security/limits.conf << 'EOF'
smtp soft nofile 65536
smtp hard nofile 65536
EOF

# Increase systemd service limit
sudo systemctl edit mail
# Add:
[Service]
LimitNOFILE=65536

sudo systemctl daemon-reload
sudo systemctl restart mail

# Verify
sudo cat /proc/$(pgrep mail)/limits | grep "open files"
```

### Issue: High Swap Usage

**Symptoms:**
- System becomes slow
- High I/O wait
- Swap usage > 50%

**Diagnosis:**
```bash
# Check swap usage
free -h
swapon --show

# Check which process is using swap
for file in /proc/*/status ; do
    awk '/VmSwap|Name/{printf $2 " " $3}END{ print ""}' $file
done | sort -k 2 -n -r | head -10
```

**Solution:**
```bash
# Reduce swappiness
sudo tee -a /etc/sysctl.d/99-smtp.conf << 'EOF'
vm.swappiness = 10
EOF
sudo sysctl -p /etc/sysctl.d/99-smtp.conf

# Add more RAM
# Or reduce memory footprint (see High Memory Usage)

# Clear swap (if possible)
sudo swapoff -a
sudo swapon -a
```

---

## Monitoring and Logging

### Issue: Metrics Not Available

**Symptoms:**
- Prometheus cannot scrape metrics
- `/metrics` endpoint returns 404 or error

**Diagnosis:**
```bash
# Check if metrics endpoint is enabled
curl http://localhost:9090/metrics

# Check if port is listening
sudo ss -tlnp | grep :9090

# Check configuration
grep METRICS /etc/smtp/smtp.env
```

**Solution:**
```bash
# Enable metrics endpoint
METRICS_ENABLED=true
METRICS_PORT=9090

# Open firewall (internal only)
sudo ufw allow from 10.0.0.0/8 to any port 9090 proto tcp

sudo systemctl restart mail

# Verify
curl http://localhost:9090/metrics | head -20
```

### Issue: Logs Not Rotating

**Symptoms:**
- Log file grows to GB in size
- Disk full due to logs
- Old logs not compressed

**Diagnosis:**
```bash
# Check log size
ls -lh /var/lib/smtp/logs/

# Check logrotate configuration
cat /etc/logrotate.d/mail

# Test logrotate
sudo logrotate -d /etc/logrotate.d/mail
```

**Solution:**
```bash
# Create logrotate configuration
sudo tee /etc/logrotate.d/mail << 'EOF'
/var/lib/smtp/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    missingok
    create 644 smtp smtp
    sharedscripts
    postrotate
        systemctl reload mail > /dev/null 2>&1 || true
    endscript
}
EOF

# Test configuration
sudo logrotate -f /etc/logrotate.d/mail

# Force rotation now
sudo logrotate -f /etc/logrotate.conf
```

### Issue: No Logs Appearing

**Symptoms:**
- Log file empty or not created
- No output in journalctl
- Cannot debug issues

**Diagnosis:**
```bash
# Check if log directory exists
ls -la /var/lib/smtp/logs/

# Check log configuration
grep LOG /etc/smtp/smtp.env

# Check file permissions
ls -la /var/lib/smtp/logs/smtp.log

# Check systemd journal
journalctl -u mail --no-pager | head -50
```

**Solution:**
```bash
# Create log directory
sudo mkdir -p /var/lib/smtp/logs
sudo chown smtp:smtp /var/lib/smtp/logs
sudo chmod 755 /var/lib/smtp/logs

# Enable logging
LOG_LEVEL=info
LOG_FILE=/var/lib/smtp/logs/smtp.log

# Create log file
sudo touch /var/lib/smtp/logs/smtp.log
sudo chown smtp:smtp /var/lib/smtp/logs/smtp.log
sudo chmod 644 /var/lib/smtp/logs/smtp.log

sudo systemctl restart mail

# Check for log output
tail -f /var/lib/smtp/logs/smtp.log
```

---

## Docker and Container Issues

### Issue: Container Fails to Start

**Symptoms:**
```
Error: failed to start container
Container exits immediately
```

**Diagnosis:**
```bash
# Check container logs
docker logs mail

# Check container status
docker ps -a | grep mail

# Inspect container
docker inspect mail
```

**Solution:**
```bash
# Check Dockerfile syntax
docker build -t mail .

# Check environment variables
docker run --rm mail env

# Run interactively for debugging
docker run -it --entrypoint /bin/sh mail

# Check volume mounts
docker volume ls
docker volume inspect smtp-data

# Remove and recreate container
docker-compose down
docker-compose up -d
```

### Issue: Container Cannot Bind to Port

**Symptoms:**
```
Error: port is already allocated
bind: address already in use
```

**Diagnosis:**
```bash
# Check what's using the port
sudo lsof -i :25
sudo ss -tlnp | grep :25

# Check docker port mappings
docker ps --format "table {{.Names}}\t{{.Ports}}"
```

**Solution:**
```bash
# Stop conflicting container
docker stop <conflicting-container>

# Or change port mapping in docker-compose.yml
ports:
  - "2525:25"  # Map host 2525 to container 25

# Use host network mode (less isolated)
network_mode: "host"

docker-compose up -d
```

### Issue: Docker Volume Permission Issues

**Symptoms:**
```
Error: Permission denied
Cannot write to /var/lib/smtp/data
```

**Diagnosis:**
```bash
# Check volume mount
docker inspect mail | grep Mounts -A 20

# Check permissions inside container
docker exec mail ls -la /var/lib/smtp/
```

**Solution:**
```bash
# Fix ownership in volume
docker exec mail chown -R smtp:smtp /var/lib/smtp

# Or specify user in docker-compose.yml
user: "1000:1000"  # smtp UID:GID

# Or use named volume with correct permissions
docker volume create --name smtp-data \
  --opt type=none \
  --opt device=/var/lib/smtp/data \
  --opt o=uid=1000,gid=1000

docker-compose up -d
```

---

## Kubernetes Issues

### Issue: Pod Not Starting

**Symptoms:**
- Pod stuck in Pending or CrashLoopBackOff
- `kubectl get pods` shows error

**Diagnosis:**
```bash
# Check pod status
kubectl get pods -n smtp-system

# Describe pod
kubectl describe pod <pod-name> -n smtp-system

# Check events
kubectl get events -n smtp-system --sort-by='.lastTimestamp'

# Check logs
kubectl logs <pod-name> -n smtp-system
```

**Solution:**
```bash
# Common causes:

# 1. Image pull error
kubectl describe pod <pod-name> -n smtp-system | grep -A 5 "Failed"
# Solution: Check image name, registry credentials

# 2. Resource limits
# Increase requests/limits in deployment.yaml
resources:
  requests:
    memory: "1Gi"
    cpu: "500m"
  limits:
    memory: "2Gi"
    cpu: "2000m"

# 3. Volume mount issues
kubectl describe pvc -n smtp-system
# Ensure PVC is bound

# 4. ConfigMap/Secret missing
kubectl get configmap -n smtp-system
kubectl get secret -n smtp-system

kubectl apply -f k8s/
```

### Issue: Service Not Accessible

**Symptoms:**
- Cannot connect to SMTP server
- LoadBalancer pending
- ClusterIP not working

**Diagnosis:**
```bash
# Check service
kubectl get svc -n smtp-system

# Check endpoints
kubectl get endpoints -n smtp-system

# Check pod selector
kubectl get pods -n smtp-system --show-labels
kubectl describe svc mail -n smtp-system | grep Selector
```

**Solution:**
```bash
# For LoadBalancer type
# Ensure cloud controller is installed
kubectl get svc mail -n smtp-system -w

# For NodePort (alternative)
kubectl patch svc mail -n smtp-system -p '{"spec":{"type":"NodePort"}}'

# For port-forward testing
kubectl port-forward -n smtp-system svc/mail 25:25

# Check network policies
kubectl get networkpolicy -n smtp-system
kubectl describe networkpolicy mail-network-policy -n smtp-system
```

### Issue: PersistentVolume Not Binding

**Symptoms:**
```
PVC status: Pending
No persistent volumes available
```

**Diagnosis:**
```bash
# Check PVC status
kubectl get pvc -n smtp-system

# Check PV
kubectl get pv

# Check storage class
kubectl get storageclass
```

**Solution:**
```bash
# Create storage class if missing
kubectl apply -f - <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: fast-ssd
provisioner: kubernetes.io/gce-pd
parameters:
  type: pd-ssd
  replication-type: regional-pd
EOF

# Or use dynamic provisioning
# Ensure provisioner is running
kubectl get pods -n kube-system | grep provisioner

# Manually create PV (if static provisioning)
kubectl apply -f k8s/pv.yaml
```

---

## Security and Firewall

### Issue: Firewall Blocking Connections

**Symptoms:**
- Connections time out from external hosts
- Internal connections work fine
- Port scan shows closed

**Diagnosis:**
```bash
# Check firewall rules
sudo iptables -L -n -v
sudo ufw status verbose

# Test from external host
telnet external-ip 25

# Check cloud security groups (AWS/GCP/Azure)
```

**Solution:**
```bash
# UFW
sudo ufw allow 25/tcp
sudo ufw allow 587/tcp
sudo ufw allow 465/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 25 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 587 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 465 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4

# AWS Security Group
aws ec2 authorize-security-group-ingress \
  --group-id sg-xxx \
  --protocol tcp \
  --port 25 \
  --cidr 0.0.0.0/0

# Verify
sudo iptables -L INPUT -n | grep -E "(25|587|465)"
```

### Issue: Fail2Ban Blocking Legitimate Users

**Symptoms:**
- Users suddenly cannot connect
- Authentication fails for valid credentials
- IP in Fail2Ban jail

**Diagnosis:**
```bash
# Check Fail2Ban status
sudo fail2ban-client status smtp-auth

# Check banned IPs
sudo fail2ban-client get smtp-auth banip --with-time

# Check logs
sudo tail -f /var/log/fail2ban.log
```

**Solution:**
```bash
# Unban IP
sudo fail2ban-client set smtp-auth unbanip 203.0.113.100

# Whitelist IP
sudo tee -a /etc/fail2ban/jail.d/smtp.conf << 'EOF'
[smtp-auth]
ignoreip = 127.0.0.1/8 ::1 203.0.113.0/24
EOF

sudo fail2ban-client reload

# Adjust ban threshold
sudo tee -a /etc/fail2ban/jail.d/smtp.conf << 'EOF'
[smtp-auth]
maxretry = 10
bantime = 600
EOF

sudo fail2ban-client reload smtp-auth
```

### Issue: SELinux Denying Operations

**Symptoms:**
```
Permission denied (SELinux)
AVC denial in audit log
```

**Diagnosis:**
```bash
# Check SELinux status
getenforce

# Check audit log
sudo ausearch -m avc -ts recent | grep smtp

# Check file contexts
ls -Z /usr/local/bin/mail
ls -Z /var/lib/smtp/
```

**Solution:**
```bash
# Set correct contexts
sudo semanage fcontext -a -t smtp_exec_t "/usr/local/bin/mail"
sudo restorecon -v /usr/local/bin/mail

sudo semanage fcontext -a -t mail_spool_t "/var/lib/smtp(/.*)?"
sudo restorecon -Rv /var/lib/smtp

# Or create custom policy
sudo audit2allow -a -M smtp-custom
sudo semodule -i smtp-custom.pp

# Temporary (not recommended)
sudo setenforce 0
```

---

## Advanced Diagnostics

### Network Packet Capture

```bash
# Capture SMTP traffic
sudo tcpdump -i any -s 0 -w smtp-capture.pcap 'port 25 or port 587 or port 465'

# Read capture
sudo tcpdump -r smtp-capture.pcap -A

# Or use Wireshark
wireshark smtp-capture.pcap
```

### Strace Process

```bash
# Trace system calls
sudo strace -p $(pgrep mail) -f -e trace=network,file

# Trace only network calls
sudo strace -p $(pgrep mail) -f -e trace=network

# Write to file
sudo strace -p $(pgrep mail) -f -o strace-output.txt
```

### Core Dump Analysis

```bash
# Enable core dumps
ulimit -c unlimited
echo "kernel.core_pattern = /tmp/core-%e-%p-%t" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Analyze core dump (if Zig has debug symbols)
# gdb /usr/local/bin/mail /tmp/core-mail-12345-1234567890
```

### Database Query Performance

```bash
# Enable query logging (SQLite)
sudo sqlite3 /var/lib/smtp/smtp.db << 'EOF'
.log stdout
.timer on
EXPLAIN QUERY PLAN SELECT * FROM messages WHERE recipient = 'user@example.com';
SELECT * FROM messages WHERE recipient = 'user@example.com' LIMIT 10;
EOF

# Analyze slow queries
# PostgreSQL
# ALTER DATABASE smtp SET log_min_duration_statement = 1000;  -- Log queries > 1s
```

### Memory Profiling

```bash
# Use valgrind (debug build)
valgrind --leak-check=full \
  --show-leak-kinds=all \
  --track-origins=yes \
  --verbose \
  --log-file=valgrind-out.txt \
  /usr/local/bin/mail

# Or use heaptrack (Linux)
heaptrack /usr/local/bin/mail
heaptrack_gui heaptrack.mail.*.gz
```

---

## Getting Help

If you cannot resolve the issue using this guide:

1. **Collect diagnostic information:**
   ```bash
   # Create diagnostic bundle
   mkdir smtp-diagnostics

   # System info
   uname -a > smtp-diagnostics/system-info.txt
   cat /etc/os-release >> smtp-diagnostics/system-info.txt

   # Service status
   systemctl status mail > smtp-diagnostics/service-status.txt

   # Logs
   journalctl -u mail -n 1000 > smtp-diagnostics/logs.txt

   # Configuration (redact passwords!)
   grep -v "PASSWORD\|KEY\|SECRET" /etc/smtp/smtp.env > smtp-diagnostics/config.txt

   # Network
   ss -tlnp > smtp-diagnostics/network.txt

   # Resources
   ps aux | grep smtp > smtp-diagnostics/processes.txt
   free -h > smtp-diagnostics/memory.txt
   df -h > smtp-diagnostics/disk.txt

   tar -czf smtp-diagnostics.tar.gz smtp-diagnostics/
   ```

2. **Search existing issues:**
   - Check GitHub issues: https://github.com/yourusername/mail/issues
   - Search documentation: docs/

3. **Report the issue:**
   - Open GitHub issue with diagnostic bundle
   - Include:
     - Problem description
     - Steps to reproduce
     - Expected vs actual behavior
     - System information
     - Relevant logs

4. **Community support:**
   - Join discussion forum/Discord/Slack
   - Ask on Stack Overflow with tag `mail`

---

## Related Documentation

- [Deployment Guide](./DEPLOYMENT.md)
- [Architecture Documentation](./ARCHITECTURE.md)
- [Performance Tuning Guide](./PERFORMANCE.md)
- [API Documentation](./API.md)
