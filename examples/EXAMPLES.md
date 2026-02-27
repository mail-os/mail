# SMTP Server Usage Examples

## Basic Usage

### Starting the Server

```bash
# Start with defaults (port 2525, localhost)
./zig-out/bin/smtp-server

# Start on a specific port
./zig-out/bin/smtp-server --port 25

# Start with debug logging
./zig-out/bin/smtp-server --log-level debug

# Start on all interfaces
./zig-out/bin/smtp-server --host 0.0.0.0 --port 2525

# IPv6 localhost
./zig-out/bin/smtp-server --host "::1" --port 2525

# IPv6 all interfaces
./zig-out/bin/smtp-server --host "::" --port 2525

# Dual-stack (IPv4 and IPv6)
./zig-out/bin/smtp-server --host "::" --port 2525  # On most systems, this binds to both
```

### Configuration via Environment Variables

```bash
# Set the host and port
export SMTP_HOST="0.0.0.0"
export SMTP_PORT="2525"

# Set the hostname
export SMTP_HOSTNAME="mail.example.com"

# Configure limits
export SMTP_MAX_CONNECTIONS="200"
export SMTP_MAX_RECIPIENTS="50"
export SMTP_MAX_MESSAGE_SIZE="20971520"  # 20MB

# Enable/disable features
export SMTP_ENABLE_TLS="true"
export SMTP_ENABLE_AUTH="true"

# Run the server
./zig-out/bin/smtp-server
```

### Command-Line Overrides

```bash
# Override environment variables with CLI args
SMTP_PORT=25 ./zig-out/bin/smtp-server --port 587 --log-level warn
```

## Testing with telnet

### Basic Connection Test

```bash
telnet localhost 2525
```

Expected output:
```
220 localhost ESMTP Service Ready
```

### Send a Test Email

```bash
telnet localhost 2525
```

Then type:
```
EHLO client.example.com
MAIL FROM:<sender@example.com>
RCPT TO:<recipient@example.com>
DATA
Subject: Test Email
From: sender@example.com
To: recipient@example.com

This is a test message.
.
QUIT
```

### Testing with swaks

```bash
# Install swaks (Swiss Army Knife for SMTP)
# macOS: brew install swaks
# Ubuntu: apt-get install swaks

# Send a test email
swaks --to recipient@example.com \
      --from sender@example.com \
      --server localhost:2525 \
      --body "Test message body" \
      --header "Subject: Test from swaks"

# Test with authentication
swaks --to recipient@example.com \
      --from sender@example.com \
      --server localhost:2525 \
      --auth PLAIN \
      --auth-user testuser \
      --auth-password testpass

# Test rate limiting (send multiple messages quickly)
for i in {1..10}; do
    swaks --to recipient@example.com \
          --from sender@example.com \
          --server localhost:2525 \
          --body "Message $i"
done
```

## Production Deployment

### Running on Port 25 (Requires Root)

```bash
# Option 1: Use sudo (not recommended for production)
sudo ./zig-out/bin/smtp-server --port 25

# Option 2: Grant capability (Linux only)
sudo setcap 'cap_net_bind_service=+ep' ./zig-out/bin/smtp-server
./zig-out/bin/smtp-server --port 25

# Option 3: Use iptables to redirect (recommended)
sudo iptables -t nat -A PREROUTING -p tcp --dport 25 -j REDIRECT --to-port 2525
./zig-out/bin/smtp-server --port 2525
```

### Running as a systemd Service

Create `/etc/systemd/system/smtp-server.service`:

```ini
[Unit]
Description=SMTP Server
After=network.target

[Service]
Type=simple
User=smtp
Group=smtp
WorkingDirectory=/opt/smtp-server
Environment="SMTP_HOST=0.0.0.0"
Environment="SMTP_PORT=2525"
Environment="SMTP_HOSTNAME=mail.example.com"
Environment="SMTP_MAX_CONNECTIONS=500"
ExecStart=/opt/smtp-server/zig-out/bin/smtp-server --log-level info
Restart=always
RestartSec=5

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/smtp-server/mail /opt/smtp-server/smtp-server.log

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable smtp-server
sudo systemctl start smtp-server
sudo systemctl status smtp-server
```

View logs:
```bash
sudo journalctl -u smtp-server -f
```

### Docker Deployment

Create `Dockerfile`:

```dockerfile
FROM alpine:latest

# Install Zig
RUN apk add --no-cache zig

# Copy source
WORKDIR /app
COPY . .

# Build
RUN zig build -Doptimize=ReleaseSafe

# Create mail directory
RUN mkdir -p /app/mail/new

# Expose SMTP port
EXPOSE 2525

# Run server
CMD ["./zig-out/bin/smtp-server", "--host", "0.0.0.0", "--port", "2525"]
```

Build and run:
```bash
# Build Docker image
docker build -t smtp-server .

# Run container
docker run -d \
  --name smtp-server \
  -p 2525:2525 \
  -v $(pwd)/mail:/app/mail \
  -v $(pwd)/smtp-server.log:/app/smtp-server.log \
  -e SMTP_HOSTNAME=mail.example.com \
  -e SMTP_MAX_CONNECTIONS=200 \
  smtp-server

# View logs
docker logs -f smtp-server

# Stop container
docker stop smtp-server
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  smtp-server:
    build: .
    ports:
      - "2525:2525"
    volumes:
      - ./mail:/app/mail
      - ./smtp-server.log:/app/smtp-server.log
    environment:
      - SMTP_HOST=0.0.0.0
      - SMTP_PORT=2525
      - SMTP_HOSTNAME=mail.example.com
      - SMTP_MAX_CONNECTIONS=200
      - SMTP_MAX_RECIPIENTS=100
      - SMTP_ENABLE_AUTH=true
    restart: unless-stopped
```

Run:
```bash
docker-compose up -d
docker-compose logs -f
```

## Monitoring

### Check Server Status

```bash
# Test if server is responding
echo "QUIT" | nc localhost 2525

# Check with swaks
swaks --server localhost:2525 --quit-after BANNER
```

### View Logs

```bash
# Real-time log viewing
tail -f smtp-server.log

# View colored logs
tail -f smtp-server.log | grep --color=always -E 'ERROR|WARN|$'

# Count errors
grep ERROR smtp-server.log | wc -l

# View rate limit violations
grep "Rate limit exceeded" smtp-server.log
```

### Monitor Received Messages

```bash
# List received messages
ls -lh mail/new/

# Count messages
ls mail/new/ | wc -l

# View latest message
cat mail/new/$(ls -t mail/new/ | head -1)

# Watch for new messages
watch -n 1 'ls -lh mail/new/ | tail -5'
```

## Security Best Practices

### Firewall Configuration

```bash
# Ubuntu/Debian (ufw)
sudo ufw allow from 192.168.1.0/24 to any port 2525
sudo ufw enable

# CentOS/RHEL (firewalld)
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="2525" protocol="tcp" accept'
sudo firewall-cmd --reload
```

### Rate Limiting at Network Level

```bash
# Limit connections per IP using iptables
sudo iptables -A INPUT -p tcp --dport 2525 -m connlimit --connlimit-above 5 -j REJECT

# Rate limit new connections
sudo iptables -A INPUT -p tcp --dport 2525 -m state --state NEW -m recent --set
sudo iptables -A INPUT -p tcp --dport 2525 -m state --state NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
```

### SSL/TLS with Reverse Proxy (nginx)

Create `/etc/nginx/sites-available/smtp-proxy`:

```nginx
stream {
    upstream smtp_backend {
        server 127.0.0.1:2525;
    }

    server {
        listen 587 ssl;
        proxy_pass smtp_backend;

        ssl_certificate /etc/letsencrypt/live/mail.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/mail.example.com/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
    }
}
```

## Troubleshooting

### Connection Refused

```bash
# Check if server is running
ps aux | grep smtp-server

# Check if port is listening
netstat -tuln | grep 2525
# or
ss -tuln | grep 2525

# Test connectivity
telnet localhost 2525
```

### Permission Denied

```bash
# Check file permissions
ls -l zig-out/bin/smtp-server

# Check port permissions (ports < 1024 require root)
# Use port 2525 or higher for non-root users
```

### Mail Not Being Saved

```bash
# Check mail directory exists
mkdir -p mail/new

# Check permissions
chmod 755 mail mail/new

# Check disk space
df -h .
```

### High Memory Usage

```bash
# Monitor memory
watch -n 1 'ps aux | grep smtp-server | grep -v grep'

# Reduce max connections
./zig-out/bin/smtp-server --max-connections 50

# Check for memory leaks in logs
grep "out of memory" smtp-server.log
```

## Performance Tuning

### Optimize for High Load

```bash
# Increase system limits (add to /etc/security/limits.conf)
*  soft  nofile  65536
*  hard  nofile  65536

# Increase max connections
./zig-out/bin/smtp-server --max-connections 1000

# Use faster log level
./zig-out/bin/smtp-server --log-level warn
```

### Load Testing

```bash
# Using smtp-source (from postfix-tools)
smtp-source -s 100 -m 1000 localhost:2525

# Monitor during load test
watch -n 1 'echo "QUIT" | nc localhost 2525 && echo "Server responsive"'
```

## Integration Examples

### Send Email from Python

```python
import smtplib
from email.message import EmailMessage

msg = EmailMessage()
msg['Subject'] = 'Test Email'
msg['From'] = 'sender@example.com'
msg['To'] = 'recipient@example.com'
msg.set_content('This is a test message.')

with smtplib.SMTP('localhost', 2525) as server:
    server.send_message(msg)
```

### Send Email from Node.js

```javascript
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    host: 'localhost',
    port: 2525,
    secure: false,
});

transporter.sendMail({
    from: 'sender@example.com',
    to: 'recipient@example.com',
    subject: 'Test Email',
    text: 'This is a test message.'
});
```

### Send Email from Bash

```bash
#!/bin/bash
{
    echo "EHLO localhost"
    echo "MAIL FROM:<sender@example.com>"
    echo "RCPT TO:<recipient@example.com>"
    echo "DATA"
    echo "Subject: Automated Email"
    echo "From: sender@example.com"
    echo "To: recipient@example.com"
    echo ""
    echo "This is an automated message."
    echo "."
    echo "QUIT"
} | nc localhost 2525
```

### Webhook Notifications

```bash
# Set up a simple webhook receiver (using Python)
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
import json

class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        data = json.loads(body)

        print(f'Mail from: {data[\"from\"]}')
        print(f'Recipients: {data[\"recipients\"]}')
        print(f'Size: {data[\"size\"]} bytes')
        print(f'Timestamp: {data[\"timestamp\"]}')
        print('---')

        self.send_response(200)
        self.end_headers()

HTTPServer(('', 8080), WebhookHandler).serve_forever()
" &

# Start SMTP server with webhook
export SMTP_WEBHOOK_URL="http://localhost:8080/webhook"
./zig-out/bin/smtp-server
```

Webhook JSON payload format:
```json
{
  "from": "sender@example.com",
  "recipients": ["recipient1@example.com", "recipient2@example.com"],
  "size": 1234,
  "timestamp": 1698765432,
  "remote_addr": "192.168.1.100"
}
```
