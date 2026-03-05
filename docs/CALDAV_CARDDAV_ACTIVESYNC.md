# CalDAV, CardDAV, and ActiveSync Guide

**Version:** v0.28.0
**Date:** 2025-10-24

## Overview

The SMTP server now includes comprehensive mobile and desktop synchronization support through three industry-standard protocols:

- **CalDAV (RFC 4791)** - Calendar synchronization via WebDAV
- **CardDAV (RFC 6352)** - Contact synchronization via WebDAV
- **ActiveSync (MS-ASHTTP)** - Microsoft Exchange ActiveSync for mobile devices

These protocols enable seamless synchronization of email, calendars, contacts, and tasks across all major platforms and devices.

---

## Features

### CalDAV (Calendar Synchronization)

- **WebDAV-based**: Built on HTTP/WebDAV for calendar access
- **iCalendar Format**: Full RFC 5545 (iCalendar) support
- **Multiple Calendars**: Support for multiple calendar collections per user
- **Recurring Events**: RRULE support for recurring calendar events
- **Shared Calendars**: Calendar sharing and delegation
- **Search and Filter**: Server-side calendar queries
- **Attendee Management**: Meeting invitations and responses
- **Timezone Support**: Proper timezone handling for global users

### CardDAV (Contact Synchronization)

- **WebDAV-based**: Built on HTTP/WebDAV for contact access
- **vCard Format**: Full RFC 6350 (vCard 4.0) support
- **Multiple Address Books**: Support for multiple contact collections
- **Contact Groups**: Distribution lists and contact groups
- **Search**: Server-side contact search
- **Photo Support**: Contact photos and avatars
- **Custom Fields**: Extensible contact properties

### Microsoft Exchange ActiveSync

- **Mobile-First**: Designed for smartphones and tablets
- **Protocol Versions**: 2.5 through 16.1 support
- **Push Email**: Real-time email delivery with PING
- **Unified Sync**: Email, calendar, contacts, tasks in one protocol
- **Policy Enforcement**: Device security policies
- **Remote Wipe**: Device management and remote wipe capability
- **Attachment Handling**: Efficient attachment synchronization
- **Search**: Global address list and mailbox search
- **Meeting Responses**: Calendar invitation handling

---

## Configuration

### CalDAV/CardDAV Configuration

```zig
const caldav_config = CalDavConfig{
    .port = 8008,                    // HTTP port
    .ssl_port = 8443,               // HTTPS port
    .enable_ssl = true,              // Enable SSL/TLS
    .max_connections = 100,          // Maximum concurrent connections
    .connection_timeout_seconds = 300, // 5 minutes
    .max_resource_size = 10 * 1024 * 1024, // 10 MB
    .calendar_path = "/var/spool/caldav/calendars",
    .contacts_path = "/var/spool/caldav/contacts",
    .enable_caldav = true,           // Enable calendar sync
    .enable_carddav = true,          // Enable contact sync
};
```

### ActiveSync Configuration

```zig
const activesync_config = ActiveSyncConfig{
    .port = 443,                     // HTTPS port (required)
    .enable_ssl = true,              // SSL is mandatory for ActiveSync
    .max_connections = 200,          // Higher for mobile devices
    .connection_timeout_seconds = 900, // 15 minutes
    .max_sync_size = 50 * 1024 * 1024, // 50 MB
    .heartbeat_interval = 540,       // 9 minutes for PING
    .policy_key = "default",
    .enable_ping = true,             // Push notifications
    .enable_search = true,           // Global search
    .enable_itemoperations = true,   // Item operations
};
```

---

## Starting the Servers

### Start CalDAV/CardDAV Server

```zig
const std = @import("std");
const caldav = @import("protocol/caldav.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = caldav.CalDavConfig{};
    var server = caldav.CalDavServer.init(allocator, config);
    defer server.deinit();

    try server.start();
}
```

### Start ActiveSync Server

```zig
const std = @import("std");
const activesync = @import("protocol/activesync.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = activesync.ActiveSyncConfig{};
    var server = activesync.ActiveSyncServer.init(allocator, config);
    defer server.deinit();

    try server.start();
}
```

### Start All Servers Together

```zig
// Start SMTP, IMAP, POP3, CalDAV, and ActiveSync concurrently
const smtp_thread = try std.Thread.spawn(.{}, startSmtpServer, .{});
const imap_thread = try std.Thread.spawn(.{}, startImapServer, .{});
const pop3_thread = try std.Thread.spawn(.{}, startPop3Server, .{});
const caldav_thread = try std.Thread.spawn(.{}, startCalDavServer, .{});
const activesync_thread = try std.Thread.spawn(.{}, startActiveSyncServer, .{});

smtp_thread.join();
imap_thread.join();
pop3_thread.join();
caldav_thread.join();
activesync_thread.join();
```

---

## CalDAV Usage

### Calendar Discovery

```bash
# Discover calendar capabilities
curl -X OPTIONS https://mail.example.com:8443/ \
  -u username:password
```

Response headers:
```
DAV: 1, 2, 3, calendar-access, addressbook
Allow: OPTIONS, GET, HEAD, POST, PUT, DELETE, PROPFIND, PROPPATCH, MKCALENDAR, MKCOL, REPORT
```

### Create a Calendar

```xml
<!-- Request -->
MKCALENDAR /calendars/user/work/ HTTP/1.1
Host: mail.example.com:8443
Content-Type: application/xml

<?xml version="1.0" encoding="utf-8" ?>
<C:mkcalendar xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set>
    <D:prop>
      <D:displayname>Work Calendar</D:displayname>
      <C:supported-calendar-component-set>
        <C:comp name="VEVENT"/>
        <C:comp name="VTODO"/>
      </C:supported-calendar-component-set>
    </D:prop>
  </D:set>
</C:mkcalendar>
```

### List Calendars

```xml
<!-- Request -->
PROPFIND /calendars/user/ HTTP/1.1
Host: mail.example.com:8443
Depth: 1
Content-Type: application/xml

<?xml version="1.0" encoding="utf-8" ?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop>
    <D:resourcetype/>
    <D:displayname/>
    <C:supported-calendar-component-set/>
  </D:prop>
</D:propfind>
```

### Create a Calendar Event

```bash
# Create event via PUT
curl -X PUT https://mail.example.com:8443/calendars/user/work/event-001.ics \
  -u username:password \
  -H "Content-Type: text/calendar" \
  --data-binary @- <<'EOF'
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Mail Server//CalDAV//EN
BEGIN:VEVENT
UID:event-001@example.com
DTSTAMP:20250124T120000Z
DTSTART:20250125T140000Z
DTEND:20250125T150000Z
SUMMARY:Team Meeting
DESCRIPTION:Weekly team sync
LOCATION:Conference Room A
ORGANIZER;CN=John Doe:mailto:john@example.com
ATTENDEE;CN=Jane Smith;RSVP=TRUE:mailto:jane@example.com
RRULE:FREQ=WEEKLY;BYDAY=TU
END:VEVENT
END:VCALENDAR
EOF
```

### Query Calendar Events

```xml
<!-- Calendar Query: All events in date range -->
REPORT /calendars/user/work/ HTTP/1.1
Host: mail.example.com:8443
Content-Type: application/xml

<?xml version="1.0" encoding="utf-8" ?>
<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop>
    <D:getetag/>
    <C:calendar-data/>
  </D:prop>
  <C:filter>
    <C:comp-filter name="VCALENDAR">
      <C:comp-filter name="VEVENT">
        <C:time-range start="20250101T000000Z" end="20250131T235959Z"/>
      </C:comp-filter>
    </C:comp-filter>
  </C:filter>
</C:calendar-query>
```

---

## CardDAV Usage

### Create an Address Book

```xml
<!-- Request -->
MKCOL /addressbooks/user/personal/ HTTP/1.1
Host: mail.example.com:8443
Content-Type: application/xml

<?xml version="1.0" encoding="utf-8" ?>
<D:mkcol xmlns:D="DAV:" xmlns:CARD="urn:ietf:params:xml:ns:carddav">
  <D:set>
    <D:prop>
      <D:resourcetype>
        <D:collection/>
        <CARD:addressbook/>
      </D:resourcetype>
      <D:displayname>Personal Contacts</D:displayname>
    </D:prop>
  </D:set>
</D:mkcol>
```

### Add a Contact

```bash
# Create contact via PUT
curl -X PUT https://mail.example.com:8443/addressbooks/user/personal/contact-001.vcf \
  -u username:password \
  -H "Content-Type: text/vcard" \
  --data-binary @- <<'EOF'
BEGIN:VCARD
VERSION:3.0
FN:John Doe
N:Doe;John;Robert;Mr.;Jr.
EMAIL;TYPE=INTERNET,WORK:john.doe@example.com
EMAIL;TYPE=INTERNET,HOME:john@personal.com
TEL;TYPE=WORK,VOICE:+1-555-123-4567
TEL;TYPE=CELL:+1-555-987-6543
ADR;TYPE=WORK:;;123 Business St;Suite 100;New York;NY;10001;USA
ORG:Acme Corporation
TITLE:Software Engineer
URL:https://johndoe.example.com
PHOTO;ENCODING=BASE64;TYPE=JPEG:/9j/4AAQ...
NOTE:Met at tech conference 2024
END:VCARD
EOF
```

### Search Contacts

```xml
<!-- Address Book Query: Search by name or email -->
REPORT /addressbooks/user/personal/ HTTP/1.1
Host: mail.example.com:8443
Content-Type: application/xml

<?xml version="1.0" encoding="utf-8" ?>
<CARD:addressbook-query xmlns:D="DAV:" xmlns:CARD="urn:ietf:params:xml:ns:carddav">
  <D:prop>
    <D:getetag/>
    <CARD:address-data/>
  </D:prop>
  <CARD:filter>
    <CARD:prop-filter name="FN">
      <CARD:text-match collation="i;unicode-casemap" match-type="contains">
        John
      </CARD:text-match>
    </CARD:prop-filter>
  </CARD:filter>
</CARD:addressbook-query>
```

---

## ActiveSync Usage

### Device Autodiscovery

```bash
# Autodiscover endpoint
curl -X POST https://mail.example.com/autodiscover/autodiscover.xml \
  -H "Content-Type: text/xml" \
  --data-binary @- <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/mobilesync/requestschema/2006">
  <Request>
    <EMailAddress>user@example.com</EMailAddress>
    <AcceptableResponseSchema>
      http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006
    </AcceptableResponseSchema>
  </Request>
</Autodiscover>
EOF
```

### Capability Discovery

```bash
# OPTIONS request to discover server capabilities
curl -X OPTIONS https://mail.example.com/Microsoft-Server-ActiveSync \
  -u username:password \
  -v
```

Response:
```
HTTP/1.1 200 OK
MS-ASProtocolVersions: 2.5,12.0,12.1,14.0,14.1,16.0,16.1
MS-ASProtocolCommands: Sync,SendMail,FolderSync,Ping,Search,ItemOperations...
```

### Folder Synchronization

```bash
# Get folder hierarchy
curl -X POST 'https://mail.example.com/Microsoft-Server-ActiveSync?Cmd=FolderSync&User=username&DeviceId=device123&DeviceType=iPhone' \
  -u username:password \
  -H "Content-Type: application/vnd.ms-sync.wbxml" \
  --data-binary @- <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<FolderSync xmlns="FolderHierarchy:">
  <SyncKey>0</SyncKey>
</FolderSync>
EOF
```

### Email Synchronization

```bash
# Sync email messages
curl -X POST 'https://mail.example.com/Microsoft-Server-ActiveSync?Cmd=Sync&User=username&DeviceId=device123&DeviceType=iPhone' \
  -u username:password \
  -H "Content-Type: application/vnd.ms-sync.wbxml" \
  --data-binary @- <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Sync xmlns="AirSync:">
  <Collections>
    <Collection>
      <SyncKey>0</SyncKey>
      <CollectionId>5</CollectionId>
    </Collection>
  </Collections>
</Sync>
EOF
```

### Push Notifications (PING)

```bash
# Enable push for new mail
curl -X POST 'https://mail.example.com/Microsoft-Server-ActiveSync?Cmd=Ping&User=username&DeviceId=device123' \
  -u username:password \
  -H "Content-Type: application/vnd.ms-sync.wbxml" \
  --data-binary @- <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Ping xmlns="Ping:">
  <HeartbeatInterval>540</HeartbeatInterval>
  <Folders>
    <Folder>
      <Id>5</Id>
      <Class>Email</Class>
    </Folder>
  </Folders>
</Ping>
EOF
```

### Send Email

```bash
# Send email via ActiveSync
curl -X POST 'https://mail.example.com/Microsoft-Server-ActiveSync?Cmd=SendMail&User=username&DeviceId=device123' \
  -u username:password \
  -H "Content-Type: message/rfc822" \
  --data-binary @- <<'EOF'
From: user@example.com
To: recipient@example.com
Subject: Test from ActiveSync
MIME-Version: 1.0
Content-Type: text/plain

This is a test email sent via ActiveSync.
EOF
```

---

## Client Configuration

### Apple Devices (iOS/macOS)

**CalDAV/CardDAV Setup:**

1. Settings → Accounts → Add Account → Other
2. Add CalDAV Account / Add CardDAV Account
   - Server: `mail.example.com`
   - Port: `8443`
   - Use SSL: Yes
   - Username: `user@example.com`
   - Password: `********`
   - Description: `Work Calendar/Contacts`

**ActiveSync Setup:**

1. Settings → Accounts → Add Account → Exchange
2. Configuration:
   - Email: `user@example.com`
   - Server: `mail.example.com`
   - Domain: (leave blank)
   - Username: `user@example.com`
   - Password: `********`

### Android Devices

**CalDAV/CardDAV Setup (DAVx⁵):**

1. Install DAVx⁵ from Play Store
2. Add Account
   - Base URL: `https://mail.example.com:8443/`
   - Username: `user@example.com`
   - Password: `********`
3. Select calendars and address books to sync

**ActiveSync Setup:**

1. Settings → Accounts → Add Account → Exchange
2. Configuration:
   - Email: `user@example.com`
   - Username: `user@example.com`
   - Password: `********`
   - Server: `mail.example.com`

### Thunderbird

**CalDAV Calendar:**

1. Calendar → New Calendar → On the Network
2. Select: CalDAV
3. Location: `https://mail.example.com:8443/calendars/user/work/`
4. Username: `user@example.com`

**CardDAV Contacts:**

1. Install CardBook add-on
2. CardBook → New Address Book → Remote
3. URL: `https://mail.example.com:8443/addressbooks/user/personal/`
4. Username: `user@example.com`

### Microsoft Outlook

**ActiveSync (Outlook for Mobile):**

1. Open Outlook app
2. Add Account → Exchange
3. Email: `user@example.com`
4. Advanced Settings:
   - Server: `mail.example.com`
   - Domain: (leave blank)
   - Username: `user@example.com`

---

## Security

### TLS/SSL Configuration

Both CalDAV/CardDAV and ActiveSync **require** HTTPS in production:

```bash
# Generate self-signed certificate (testing only)
openssl req -x509 -newkey rsa:4096 \
  -keyout caldav_key.pem \
  -out caldav_cert.pem \
  -days 365 -nodes \
  -subj "/CN=mail.example.com"

# Production: Use Let's Encrypt
certbot certonly --standalone -d mail.example.com
```

### Authentication

All three protocols support:
- **Basic Authentication**: Username/password over HTTPS
- **OAuth 2.0**: Token-based authentication (future)
- **Two-Factor Authentication**: Additional security layer (future)

### ActiveSync Security Policies

```xml
<!-- Device Policy Example -->
<EASProvisionDoc>
  <DevicePasswordEnabled>1</DevicePasswordEnabled>
  <AlphanumericDevicePasswordRequired>1</AlphanumericDevicePasswordRequired>
  <MinDevicePasswordLength>8</MinDevicePasswordLength>
  <MaxInactivityTimeDeviceLock>300</MaxInactivityTimeDeviceLock>
  <MaxDevicePasswordFailedAttempts>5</MaxDevicePasswordFailedAttempts>
  <AllowSimpleDevicePassword>0</AllowSimpleDevicePassword>
  <DevicePasswordExpiration>90</DevicePasswordExpiration>
  <DevicePasswordHistory>5</DevicePasswordHistory>
</EASProvisionDoc>
```

---

## Performance Tuning

### CalDAV/CardDAV Optimization

```zig
const caldav_config = CalDavConfig{
    .max_connections = 500,          // High concurrency
    .connection_timeout_seconds = 600, // 10 minutes
    .max_resource_size = 50 * 1024 * 1024, // 50 MB for large vCards
};
```

### ActiveSync Optimization

```zig
const activesync_config = ActiveSyncConfig{
    .max_connections = 1000,         // Many mobile devices
    .heartbeat_interval = 900,       // 15 minutes (battery optimization)
    .max_sync_size = 100 * 1024 * 1024, // 100 MB
};
```

### Caching Strategy

```zig
// Cache ETags for efficient synchronization
const etag_cache = std.StringHashMap([]const u8).init(allocator);

// Only send changed resources
if (client_etag != server_etag) {
    // Send full resource
} else {
    // Send 304 Not Modified
}
```

---

## Troubleshooting

### CalDAV/CardDAV Issues

**Problem**: Client can't discover calendars

**Solutions**:
1. Verify WebDAV endpoint: `curl -X OPTIONS https://mail.example.com:8443/`
2. Check DAV header in response
3. Verify SSL certificate is valid
4. Test PROPFIND manually

**Problem**: Events not syncing

**Solutions**:
1. Check iCalendar format validity
2. Verify ETags are being updated
3. Check client sync interval
4. Look for timezone issues

### ActiveSync Issues

**Problem**: Device can't connect

**Solutions**:
1. Verify OPTIONS response includes MS-ASProtocolVersions
2. Check device is using supported protocol version
3. Verify SSL certificate
4. Check device ID is being sent

**Problem**: Push notifications not working

**Solutions**:
1. Verify PING is enabled in config
2. Check heartbeat interval (usually 9-15 minutes)
3. Verify firewall allows long-lived connections
4. Check mobile device power settings

**Problem**: Mail not syncing

**Solutions**:
1. Check SyncKey is valid
2. Verify CollectionId matches folder
3. Look for sync conflicts
4. Check filter settings on device

---

## Protocol Compliance

### CalDAV Standards

- **RFC 4791**: CalDAV (Calendaring Extensions to WebDAV)
- **RFC 5545**: iCalendar
- **RFC 6638**: Scheduling Extensions to CalDAV
- **RFC 7809**: CalDAV Time Zone Extensions

### CardDAV Standards

- **RFC 6352**: CardDAV (vCard Extensions to WebDAV)
- **RFC 6350**: vCard Format Specification
- **RFC 6764**: Locating Services for CalDAV and CardDAV

### ActiveSync Standards

- **MS-ASHTTP**: ActiveSync HTTP Protocol
- **MS-ASCMD**: ActiveSync Command Reference Protocol
- **MS-ASWBXML**: ActiveSync WBXML Protocol
- **MS-ASPROV**: ActiveSync Provisioning Protocol

---

## Monitoring and Logging

### Metrics to Track

**CalDAV/CardDAV**:
- Active connections
- PROPFIND requests per second
- Resource creation/update/delete rates
- Average response time
- Cache hit ratio

**ActiveSync**:
- Active devices
- Sync operations per minute
- PING connections (push users)
- Policy compliance rate
- Average sync payload size

### Logging Example

```zig
std.debug.print("[CalDAV] PROPFIND {} from {} - {d}ms\n", .{
    path,
    client_ip,
    response_time_ms,
});

std.debug.print("[ActiveSync] Sync device={s} folder={s} items={d}\n", .{
    device_id,
    folder_id,
    sync_item_count,
});
```

---

## Migration

### From Google Calendar/Contacts

1. Export Google Calendar to .ics files
2. Export Google Contacts to vCard (.vcf)
3. Import via CalDAV/CardDAV PUT requests
4. Configure clients to use new server

### From Exchange Server

1. Export user mailboxes
2. Convert calendar/contact data
3. Configure ActiveSync autodiscovery DNS
4. Update client configurations
5. Test ActiveSync connectivity

---

## See Also

- [IMAP and POP3 Guide](IMAP_POP3.md)
- [SMTP Protocol Documentation](SMTP.md)
- [Security Guide](SECURITY.md)
- [API Reference](API_REFERENCE.md)

---

**Last Updated:** 2025-10-24
**Version:** v0.28.0
