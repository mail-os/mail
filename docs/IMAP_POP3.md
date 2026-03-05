# IMAP and POP3 Server Guide

**Version:** v0.28.0
**Date:** 2025-10-24

## Overview

The Mail Server now includes built-in IMAP4rev1 and POP3 support for complete mail retrieval functionality. Users can send mail via SMTP and retrieve it using either IMAP or POP3 clients.

## Features

### IMAP4rev1 (RFC 3501)

- **Protocol Compliance**: Full IMAP4rev1 implementation
- **Multiple Mailboxes**: Support for INBOX and custom folders
- **Message Flags**: \\Seen, \\Answered, \\Flagged, \\Deleted, \\Draft, \\Recent
- **Search**: Server-side message searching
- **IDLE**: Push notifications for new mail (RFC 2177)
- **UIDPLUS**: Efficient message operations
- **SSL/TLS**: Secure connections via STARTTLS or IMAPS (port 993)
- **Authentication**: PLAIN, LOGIN support

### POP3 (RFC 1939)

- **Protocol Compliance**: Full POP3 implementation
- **APOP**: Secure authentication via APOP
- **UIDL**: Unique message identifiers
- **TOP**: Retrieve message headers + N lines
- **SSL/TLS**: Secure connections via POP3S (port 995)
- **Multi-drop**: Support for multiple users
- **Message Deletion**: Delete messages on server

---

## Configuration

### IMAP Configuration

```zig
const imap_config = ImapConfig{
    .port = 143,              // Standard IMAP port
    .ssl_port = 993,          // IMAPS port
    .enable_ssl = true,       // Enable SSL/TLS
    .max_connections = 100,   // Maximum concurrent connections
    .connection_timeout_seconds = 300,  // 5 minutes
    .idle_timeout_seconds = 1800,       // 30 minutes
    .max_message_size = 50 * 1024 * 1024, // 50 MB
    .mailbox_path = "/var/spool/mail",
};
```

### POP3 Configuration

```zig
const pop3_config = Pop3Config{
    .port = 110,              // Standard POP3 port
    .ssl_port = 995,          // POP3S port
    .enable_ssl = true,       // Enable SSL/TLS
    .max_connections = 50,    // Maximum concurrent connections
    .connection_timeout_seconds = 600,  // 10 minutes
    .max_message_size = 50 * 1024 * 1024, // 50 MB
    .mailbox_path = "/var/spool/mail",
    .delete_on_quit = true,   // Delete messages marked for deletion
};
```

---

## Starting the Servers

### Start IMAP Server

```zig
const std = @import("std");
const imap = @import("protocol/imap.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = imap.ImapConfig{};
    var server = imap.ImapServer.init(allocator, config);
    defer server.deinit();

    try server.start();
}
```

### Start POP3 Server

```zig
const std = @import("std");
const pop3 = @import("protocol/pop3.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = pop3.Pop3Config{};
    var server = pop3.Pop3Server.init(allocator, config);
    defer server.deinit();

    try server.start();
}
```

### Start All Servers Together

```zig
// Start SMTP, IMAP, and POP3 concurrently
const smtp_thread = try std.Thread.spawn(.{}, startSmtpServer, .{});
const imap_thread = try std.Thread.spawn(.{}, startImapServer, .{});
const pop3_thread = try std.Thread.spawn(.{}, startPop3Server, .{});

smtp_thread.join();
imap_thread.join();
pop3_thread.join();
```

---

## IMAP Usage Examples

### Connect and Authenticate

```bash
# Connect via telnet (testing)
telnet localhost 143

# Server responds:
* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] Mail Server IMAP4rev1 ready

# Login
A001 LOGIN username password
A001 OK LOGIN completed

# Or use openssl for TLS
openssl s_client -connect localhost:993
```

### List Capabilities

```
A002 CAPABILITY
* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN AUTH=LOGIN IDLE NAMESPACE UIDPLUS
A002 OK CAPABILITY completed
```

### Select Mailbox

```
A003 SELECT INBOX
* 5 EXISTS
* 2 RECENT
* OK [UIDVALIDITY 1698765432]
* OK [UIDNEXT 6]
* FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
* OK [PERMANENTFLAGS (\Answered \Flagged \Deleted \Seen \Draft \*)]
A003 OK [READ-WRITE] SELECT completed
```

### Fetch Messages

```
# Fetch all flags
A004 FETCH 1:* FLAGS
* 1 FETCH (FLAGS (\Seen))
* 2 FETCH (FLAGS (\Recent))
* 3 FETCH (FLAGS (\Answered \Seen))
A004 OK FETCH completed

# Fetch message headers
A005 FETCH 1 BODY[HEADER]
* 1 FETCH (BODY[HEADER] {123}
From: sender@example.com
To: recipient@example.com
Subject: Test Message
...
)
A005 OK FETCH completed

# Fetch full message
A006 FETCH 1 BODY[]
* 1 FETCH (BODY[] {456}
...entire message...
)
A006 OK FETCH completed
```

### Search Messages

```
# Search for unseen messages
A007 SEARCH UNSEEN
* SEARCH 2 4 5
A007 OK SEARCH completed

# Search by subject
A008 SEARCH SUBJECT "important"
* SEARCH 1 3
A008 OK SEARCH completed

# Search by date
A009 SEARCH SINCE 1-Jan-2024
* SEARCH 4 5
A009 OK SEARCH completed
```

### Set Message Flags

```
# Mark message as seen
A010 STORE 1 +FLAGS (\Seen)
* 1 FETCH (FLAGS (\Seen))
A010 OK STORE completed

# Mark message as deleted
A011 STORE 2 +FLAGS (\Deleted)
* 2 FETCH (FLAGS (\Deleted))
A011 OK STORE completed

# Expunge deleted messages
A012 EXPUNGE
* 2 EXPUNGE
A012 OK EXPUNGE completed
```

### Create and Manage Mailboxes

```
# Create new mailbox
A013 CREATE Work
A013 OK CREATE completed

# List mailboxes
A014 LIST "" "*"
* LIST () "/" INBOX
* LIST () "/" Work
* LIST () "/" Sent
A014 OK LIST completed

# Subscribe to mailbox
A015 SUBSCRIBE Work
A015 OK SUBSCRIBE completed

# Delete mailbox
A016 DELETE OldStuff
A016 OK DELETE completed
```

### IDLE (Push Notifications)

```
# Enter IDLE mode
A017 IDLE
+ idling

# Server sends updates when new mail arrives:
* 6 EXISTS
* 6 RECENT

# Exit IDLE mode
DONE
A017 OK IDLE completed
```

### Logout

```
A999 LOGOUT
* BYE IMAP4rev1 Server logging out
A999 OK LOGOUT completed
```

---

## POP3 Usage Examples

### Connect and Authenticate

```bash
# Connect via telnet
telnet localhost 110

# Server responds:
+OK POP3 server ready

# Authenticate
USER username
+OK User accepted

PASS password
+OK Mailbox locked and ready
```

### Get Mailbox Statistics

```
STAT
+OK 3 3584
```

This shows 3 messages with a total size of 3584 octets.

### List Messages

```
# List all messages
LIST
+OK 3 messages (3584 octets)
1 1024
2 1536
3 1024
.

# List specific message
LIST 1
+OK 1 1024
```

### Retrieve Messages

```
# Retrieve full message
RETR 1
+OK 1024 octets
From: sender@example.com
To: recipient@example.com
Subject: Test Message

Message body here...
.

# Retrieve message headers + N lines
TOP 1 10
+OK Top of message follows
From: sender@example.com
To: recipient@example.com
Subject: Test Message

First 10 lines of message body...
.
```

### Get Unique Message IDs

```
# Get all UIDLs
UIDL
+OK Unique-ID listing follows
1 msg-001
2 msg-002
3 msg-003
.

# Get specific UIDL
UIDL 1
+OK 1 msg-001
```

### Delete Messages

```
# Mark message for deletion
DELE 1
+OK Message deleted

# Undelete all messages
RSET
+OK Maildrop has been reset
```

### Disconnect

```
QUIT
+OK POP3 server signing off (1 messages deleted)
```

Messages marked for deletion are permanently removed.

---

## Client Configuration

### Thunderbird

**IMAP:**
- Server: mail.example.com
- Port: 143 (STARTTLS) or 993 (SSL/TLS)
- Connection security: STARTTLS or SSL/TLS
- Authentication: Normal password

**POP3:**
- Server: mail.example.com
- Port: 110 (STARTTLS) or 995 (SSL/TLS)
- Connection security: STARTTLS or SSL/TLS
- Authentication: Normal password

### Apple Mail

**IMAP:**
- Incoming Mail Server: mail.example.com
- Port: 993
- Use SSL: Yes
- Authentication: Password

**POP3:**
- Incoming Mail Server: mail.example.com
- Port: 995
- Use SSL: Yes
- Authentication: Password

### Gmail App (Mobile)

**IMAP:**
- Server: mail.example.com:993
- Security type: SSL/TLS
- Authentication: Password

---

## Security

### TLS/SSL Configuration

```zig
// Enable STARTTLS for IMAP
const imap_config = ImapConfig{
    .enable_ssl = true,
    .ssl_port = 993,
    // ... other config
};

// Enable POP3S
const pop3_config = Pop3Config{
    .enable_ssl = true,
    .ssl_port = 995,
    // ... other config
};
```

### Certificate Setup

```bash
# Generate self-signed certificate (testing only)
openssl req -x509 -newkey rsa:4096 \
  -keyout imap_key.pem \
  -out imap_cert.pem \
  -days 365 -nodes

# Use in production with Let's Encrypt
certbot certonly --standalone -d mail.example.com
```

### Authentication

Both IMAP and POP3 support:
- **PLAIN**: Username/password in plaintext (use with TLS!)
- **LOGIN**: Base64-encoded username/password
- **APOP** (POP3 only): MD5-based authentication

---

## Performance Tuning

### IMAP Optimization

```zig
const imap_config = ImapConfig{
    .max_connections = 500,        // High concurrency
    .idle_timeout_seconds = 3600,  // 1 hour IDLE
    .max_message_size = 100 * 1024 * 1024, // 100 MB
};
```

### POP3 Optimization

```zig
const pop3_config = Pop3Config{
    .max_connections = 200,        // POP3 typically fewer connections
    .connection_timeout_seconds = 300, // 5 minutes
};
```

### System Limits

```bash
# Increase file descriptors
ulimit -n 65536

# Kernel tuning
sysctl -w net.core.somaxconn=4096
sysctl -w net.ipv4.tcp_max_syn_backlog=8192
```

---

## Monitoring

### IMAP Metrics

- Active connections
- Messages per mailbox
- Search query performance
- IDLE connections
- Authentication failures

### POP3 Metrics

- Active sessions
- Messages downloaded
- Deletion rate
- Authentication failures

### Logging

```zig
// Enable debug logging
std.debug.print("[IMAP] Client connected from {}\n", .{client_address});
std.debug.print("[POP3] User {} authenticated\n", .{username});
```

---

## Troubleshooting

### IMAP Issues

**Problem**: Client can't connect

**Solutions**:
1. Check firewall: `sudo ufw allow 143/tcp`
2. Verify server is running: `netstat -tlnp | grep 143`
3. Test connection: `telnet localhost 143`

**Problem**: Messages not appearing

**Solutions**:
1. Check mailbox path permissions
2. Verify UIDVALIDITY hasn't changed
3. Force mailbox rescan: `SELECT INBOX`

### POP3 Issues

**Problem**: Messages downloaded multiple times

**Solutions**:
1. Enable UIDL support in client
2. Check `delete_on_quit` setting
3. Verify maildrop locking works

**Problem**: Authentication fails

**Solutions**:
1. Check username/password
2. Verify user exists in system
3. Check authentication logs
4. Test with PLAIN auth over TLS

---

## Migration

### From Dovecot

1. Export mailboxes to Maildir format
2. Copy to server's mailbox_path
3. Update client settings to new server
4. Test with IMAP/POP3 clients

### From Courier

1. Maildir format is compatible
2. Copy user mailboxes
3. Update DNS MX records
4. Migrate clients

---

## See Also

- [SMTP Protocol Documentation](SMTP.md)
- [Security Guide](SECURITY.md)
- [Deployment Runbook](DEPLOYMENT_RUNBOOK.md)

---

**Last Updated:** 2025-10-24
**Version:** v0.28.0
