# TLS Proxy Setup Guide

**Version:** v0.21.0
**Date:** 2025-10-24

## Overview

Due to a known issue with the STARTTLS handshake cipher implementation (see [KNOWN_ISSUES_AND_SOLUTIONS.md](./KNOWN_ISSUES_AND_SOLUTIONS.md)), the **recommended production deployment** is to use a reverse proxy for TLS termination.

This approach provides:
- ✅ **Stable TLS**: Battle-tested TLS implementations (OpenSSL/BoringSSL)
- ✅ **Better Performance**: Optimized TLS handling
- ✅ **Certificate Management**: Let's Encrypt integration
- ✅ **Load Balancing**: Built-in load balancing capabilities
- ✅ **Monitoring**: Better observability and metrics

## Quick Start

### Option 1: nginx (Recommended)

**Best for:** Simple deployments, most common use case

```nginx
stream {
    upstream smtp_backend {
        server 127.0.0.1:2525;  # SMTP server on non-standard port
    }

    server {
        listen 587 ssl;
        proxy_pass smtp_backend;
        proxy_timeout 600s;      # 10 minutes for long DATA commands
        proxy_connect_timeout 5s;

        # TLS Configuration
        ssl_certificate /etc/ssl/certs/mail.example.com.crt;
        ssl_certificate_key /etc/ssl/private/mail.example.com.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;

        # Optional: Client certificate verification
        # ssl_verify_client optional;
        # ssl_client_certificate /etc/ssl/certs/ca.crt;
    }
}
```

### Option 2: HAProxy

**Best for:** High availability, advanced load balancing

```haproxy
frontend smtp_tls
    bind *:587 ssl crt /etc/ssl/mail.example.com.pem
    mode tcp
    option tcplog
    timeout client 600s
    default_backend smtp_servers

backend smtp_servers
    mode tcp
    option tcplog
    timeout connect 5s
    timeout server 600s
    server smtp1 127.0.0.1:2525 check
    # Add more servers for load balancing:
    # server smtp2 127.0.0.1:2526 check
    # server smtp3 127.0.0.1:2527 check
```

### Option 3: Caddy

**Best for:** Automatic HTTPS, simple configuration

```caddyfile
mail.example.com:587 {
    reverse_proxy 127.0.0.1:2525 {
        transport tcp
        timeout {
            dial 5s
            read 600s
            write 600s
        }
    }

    tls {
        protocols tls1.2 tls1.3
    }
}
```

## Detailed Setup Instructions

### nginx Setup

#### 1. Install nginx

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install nginx
```

**RHEL/CentOS:**
```bash
sudo yum install nginx
```

**macOS:**
```bash
brew install nginx
```

#### 2. Configure nginx for SMTP

Create `/etc/nginx/conf.d/smtp.conf`:

```nginx
stream {
    # Logging
    log_format smtp '$remote_addr [$time_local] '
                    '$protocol $status $bytes_sent $bytes_received '
                    '$session_time "$upstream_addr" '
                    '"$upstream_bytes_sent" "$upstream_bytes_received" "$upstream_connect_time"';

    access_log /var/log/nginx/smtp-access.log smtp;
    error_log /var/log/nginx/smtp-error.log;

    # Upstream SMTP server
    upstream smtp_backend {
        server 127.0.0.1:2525 max_fails=3 fail_timeout=30s;
        # For load balancing, add more servers:
        # server 127.0.0.1:2526 max_fails=3 fail_timeout=30s;
        # least_conn;  # Use least connections algorithm
    }

    # SMTP Submission (Port 587)
    server {
        listen 587 ssl;
        listen [::]:587 ssl;

        proxy_pass smtp_backend;
        proxy_timeout 600s;
        proxy_connect_timeout 5s;
        proxy_buffer_size 16k;

        # TLS Configuration
        ssl_certificate /etc/ssl/certs/mail.example.com.crt;
        ssl_certificate_key /etc/ssl/private/mail.example.com.key;

        # Modern TLS configuration
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
        ssl_prefer_server_ciphers on;

        # SSL session cache
        ssl_session_cache shared:SMTP_SSL:10m;
        ssl_session_timeout 10m;

        # OCSP stapling
        ssl_stapling on;
        ssl_stapling_verify on;
        ssl_trusted_certificate /etc/ssl/certs/ca-bundle.crt;
    }

    # Optional: SMTPS (Port 465) - Implicit TLS
    server {
        listen 465 ssl;
        listen [::]:465 ssl;

        proxy_pass smtp_backend;
        proxy_timeout 600s;
        proxy_connect_timeout 5s;

        ssl_certificate /etc/ssl/certs/mail.example.com.crt;
        ssl_certificate_key /etc/ssl/private/mail.example.com.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
    }
}
```

#### 3. Test nginx configuration

```bash
sudo nginx -t
```

#### 4. Reload nginx

```bash
sudo systemctl reload nginx
```

#### 5. Configure firewall

```bash
# UFW (Ubuntu)
sudo ufw allow 587/tcp
sudo ufw allow 465/tcp

# firewalld (RHEL/CentOS)
sudo firewall-cmd --permanent --add-service=smtp-submission
sudo firewall-cmd --reload
```

---

### HAProxy Setup

#### 1. Install HAProxy

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install haproxy
```

**RHEL/CentOS:**
```bash
sudo yum install haproxy
```

#### 2. Create combined certificate

HAProxy requires certificate and key in one file:

```bash
cat /etc/ssl/certs/mail.example.com.crt \
    /etc/ssl/private/mail.example.com.key \
    > /etc/ssl/private/mail.example.com.pem
chmod 600 /etc/ssl/private/mail.example.com.pem
```

#### 3. Configure HAProxy

Edit `/etc/haproxy/haproxy.cfg`:

```haproxy
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

    # SSL Configuration
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    log     global
    mode    tcp
    option  tcplog
    option  dontlognull
    timeout connect 5s
    timeout client  600s
    timeout server  600s

# SMTP Submission Frontend (Port 587)
frontend smtp_submission
    bind *:587 ssl crt /etc/ssl/private/mail.example.com.pem
    mode tcp
    option tcplog
    default_backend smtp_servers

# SMTP Backend
backend smtp_servers
    mode tcp
    option tcplog
    option tcp-check
    balance leastconn

    # Health check
    tcp-check connect port 2525

    # Backend servers
    server smtp1 127.0.0.1:2525 check inter 10s fall 3 rise 2
    # Add more for load balancing:
    # server smtp2 127.0.0.1:2526 check inter 10s fall 3 rise 2
    # server smtp3 127.0.0.1:2527 check inter 10s fall 3 rise 2

# Optional: Stats page
listen stats
    bind *:8404
    mode http
    stats enable
    stats uri /stats
    stats refresh 30s
    stats admin if TRUE
```

#### 4. Test and restart

```bash
sudo haproxy -c -f /etc/haproxy/haproxy.cfg
sudo systemctl restart haproxy
```

---

### Let's Encrypt / Certbot Integration

#### Automatic certificate management with nginx

```bash
# Install certbot
sudo apt-get install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot certonly --nginx -d mail.example.com

# Certificates will be at:
# /etc/letsencrypt/live/mail.example.com/fullchain.pem
# /etc/letsencrypt/live/mail.example.com/privkey.pem

# Update nginx config to use these paths
sudo nano /etc/nginx/conf.d/smtp.conf
```

Update certificate paths in nginx config:

```nginx
ssl_certificate /etc/letsencrypt/live/mail.example.com/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/mail.example.com/privkey.pem;
```

#### Auto-renewal

Certbot sets up auto-renewal automatically. Test it:

```bash
sudo certbot renew --dry-run
```

After renewal, reload nginx:

```bash
# Create renewal hook
sudo nano /etc/letsencrypt/renewal-hooks/post/reload-nginx.sh
```

Add:

```bash
#!/bin/bash
systemctl reload nginx
```

Make executable:

```bash
sudo chmod +x /etc/letsencrypt/renewal-hooks/post/reload-nginx.sh
```

---

## Mail Server Configuration

Configure the SMTP server to listen on a non-privileged port:

### Environment Variables

```bash
# .env or /etc/mail/config
SMTP_HOST=127.0.0.1
SMTP_PORT=2525
SMTP_ENABLE_TLS=false   # Disable native TLS (proxy handles it)
SMTP_ENABLE_AUTH=true   # Keep authentication enabled
```

### systemd Service

```ini
# /etc/systemd/system/mail.service
[Unit]
Description=Mail Server (Behind TLS Proxy)
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

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/mail

[Install]
WantedBy=multi-user.target
```

---

## Load Balancing Setup

### Multiple Mail Server Instances

Run multiple instances on different ports:

**Instance 1:**
```bash
SMTP_PORT=2525 ./mail
```

**Instance 2:**
```bash
SMTP_PORT=2526 ./mail
```

**Instance 3:**
```bash
SMTP_PORT=2527 ./mail
```

### nginx Load Balancing

```nginx
upstream smtp_backend {
    least_conn;  # Use least connections algorithm
    server 127.0.0.1:2525 max_fails=3 fail_timeout=30s weight=1;
    server 127.0.0.1:2526 max_fails=3 fail_timeout=30s weight=1;
    server 127.0.0.1:2527 max_fails=3 fail_timeout=30s weight=1;
}
```

### HAProxy Load Balancing

```haproxy
backend smtp_servers
    balance leastconn
    server smtp1 127.0.0.1:2525 check weight 100
    server smtp2 127.0.0.1:2526 check weight 100
    server smtp3 127.0.0.1:2527 check weight 100
```

---

## Monitoring & Logging

### nginx Monitoring

**Access logs:**
```bash
tail -f /var/log/nginx/smtp-access.log
```

**Error logs:**
```bash
tail -f /var/log/nginx/smtp-error.log
```

**Connection stats:**
```bash
# Install nginx-module-stream
# Add to nginx.conf:
server {
    listen 8080;
    location /stub_status {
        stub_status;
    }
}
```

### HAProxy Monitoring

**Stats page:**
- Visit `http://your-server:8404/stats`

**Logs:**
```bash
tail -f /var/log/haproxy.log
```

---

## Troubleshooting

### Common Issues

#### 1. Connection Refused

**Symptom:** `connect() failed (111: Connection refused)`

**Solution:**
- Ensure SMTP server is running: `systemctl status mail`
- Check if listening on correct port: `netstat -tuln | grep 2525`
- Verify firewall rules

#### 2. SSL Certificate Errors

**Symptom:** `SSL certificate problem: unable to get local issuer certificate`

**Solution:**
- Check certificate path in config
- Verify certificate is valid: `openssl s_client -connect mail.example.com:587 -starttls smtp`
- Ensure intermediate certificates are included

#### 3. Timeout Errors

**Symptom:** `upstream timed out (110: Connection timed out)`

**Solution:**
- Increase `proxy_timeout` in nginx (default: 600s for DATA command)
- Check SMTP server logs for slow operations
- Verify `SMTP_DATA_TIMEOUT_SECONDS` is set appropriately

#### 4. Performance Issues

**Symptom:** Slow connections, high latency

**Solution:**
- Enable keepalive connections:
  ```nginx
  upstream smtp_backend {
      server 127.0.0.1:2525;
      keepalive 32;
  }
  ```
- Increase worker connections in nginx:
  ```nginx
  events {
      worker_connections 1024;
  }
  ```
- Monitor system resources (CPU, memory, network)

---

## Security Considerations

### 1. Firewall Rules

Only allow external access to proxy ports:

```bash
# Block direct access to SMTP server port
iptables -A INPUT -p tcp --dport 2525 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 2525 -j DROP

# Allow proxy ports
iptables -A INPUT -p tcp --dport 587 -j ACCEPT
iptables -A INPUT -p tcp --dport 465 -j ACCEPT
```

### 2. TLS Best Practices

- Use TLS 1.2 or higher
- Disable weak ciphers
- Enable OCSP stapling
- Implement certificate pinning for clients (optional)
- Rotate certificates regularly

### 3. Rate Limiting

Add rate limiting in nginx:

```nginx
stream {
    # Define rate limit zone
    limit_conn_zone $binary_remote_addr zone=smtp_conn:10m;

    server {
        listen 587 ssl;
        proxy_pass smtp_backend;

        # Limit to 10 concurrent connections per IP
        limit_conn smtp_conn 10;
    }
}
```

### 4. DDoS Protection

```nginx
# Connection rate limiting
limit_conn_zone $binary_remote_addr zone=addr:10m;
limit_conn addr 5;

# Request rate limiting (connections per second)
limit_req_zone $binary_remote_addr zone=req:10m rate=10r/s;
limit_req zone=req burst=20 nodelay;
```

---

## Performance Tuning

### nginx Tuning

```nginx
# nginx.conf
worker_processes auto;
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    use epoll;  # Linux
    # use kqueue;  # BSD/macOS
    multi_accept on;
}

stream {
    # Increase buffer sizes
    proxy_buffer_size 16k;

    # TCP optimizations
    tcp_nodelay on;

    # Connection pooling
    upstream smtp_backend {
        server 127.0.0.1:2525;
        keepalive 64;
    }
}
```

### HAProxy Tuning

```haproxy
global
    maxconn 50000
    tune.bufsize 32768
    tune.maxrewrite 8192

defaults
    timeout connect 5s
    timeout client 600s
    timeout server 600s
    maxconn 3000
```

### OS-Level Tuning

```bash
# /etc/sysctl.conf
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.ip_local_port_range = 1024 65535

# Apply
sudo sysctl -p
```

---

## Testing

### Test TLS Connection

```bash
# Test with openssl
openssl s_client -connect mail.example.com:587 -starttls smtp

# Test with swaks
swaks --to test@example.com \
      --from sender@example.com \
      --server mail.example.com:587 \
      --tls-on-connect \
      --auth PLAIN \
      --auth-user username \
      --auth-password password
```

### Load Testing

```bash
# Install smtp-source (from Postfix)
smtp-source -c 100 -l 1000 -m 10000 mail.example.com:587
```

---

## Migration Path

When native STARTTLS is fixed in a future release:

1. Test native TLS in development
2. Run A/B test with mixed proxy/native deployment
3. Gradually migrate traffic to native TLS
4. Keep proxy as fallback option

---

## Additional Resources

- [nginx Stream Module Documentation](http://nginx.org/en/docs/stream/ngx_stream_core_module.html)
- [HAProxy Configuration Manual](https://www.haproxy.org/download/2.8/doc/configuration.txt)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [SQLite WAL Mode](https://www.sqlite.org/wal.html)

---

**Last Updated:** 2025-10-24
**Version:** v0.21.0
