# Email Client Autoconfiguration

**Source:** `src/api/autoconfig.zig`

## Overview

Email client autoconfiguration allows users to set up their mail accounts by
entering only their email address and password. The server automatically provides
the correct IMAP, SMTP, and POP3 settings. Three major discovery protocols are
supported, covering Thunderbird/Mozilla, Outlook/Microsoft, and Apple clients.

## Supported Protocols

### Thunderbird / Mozilla Autoconfig

Served at:
- `/.well-known/autoconfig/mail/config-v1.1.xml`
- `/mail/config-v1.1.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="example.com">
    <domain>example.com</domain>
    <displayName>Example Mail</displayName>
    <displayShortName>Example</displayShortName>
    <incomingServer type="imap">
      <hostname>mail.example.com</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>mail.example.com</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>
```

### Outlook / Microsoft Autodiscover

Served at:
- `/autodiscover/autodiscover.xml`
- `/Autodiscover/Autodiscover.xml`

Outlook sends a POST request with an XML body containing the user's email address.
The server responds with protocol settings:

The response XML contains `<Protocol>` blocks for IMAP (port 993, SSL) and
SMTP (port 587, TLS) with the user's login name.

### Apple Mobileconfig

Served at:
- `/email.mobileconfig`
- `/.well-known/autoconfig/email.mobileconfig`

Apple devices use a Configuration Profile (`.mobileconfig`) that bundles IMAP and
SMTP account settings into a signed XML plist. When a user opens the profile, iOS
or macOS prompts them to install it, automatically creating the mail account.

## Configuration

### Environment Variable

```bash
SMTP_ENABLE_AUTOCONFIG=true
```

### Configuration File

```ini
[autoconfig]
enabled = true
```

### Programmatic Configuration

```zig
const config = AutoconfigConfig{
    .hostname = "mail.example.com",
    .domain = "example.com",
    .imap_port = 143,
    .imaps_port = 993,
    .smtp_port = 587,
    .pop3_port = 995,
    .enable_imap = true,
    .enable_pop3 = false,
    .display_name = "Example Mail",
    .display_short_name = "Example",
};
```

### Configuration Fields

| Field | Default | Description |
|-------|---------|-------------|
| `hostname` | `localhost` | Mail server hostname advertised to clients |
| `domain` | `localhost` | Primary domain served by this mail server |
| `imap_port` | `143` | IMAP STARTTLS port |
| `imaps_port` | `993` | IMAPS (implicit TLS) port |
| `smtp_port` | `587` | SMTP submission port (STARTTLS) |
| `pop3_port` | `995` | POP3S (implicit TLS) port |
| `enable_imap` | `true` | Advertise IMAP in autoconfiguration responses |
| `enable_pop3` | `false` | Advertise POP3 in autoconfiguration responses |
| `display_name` | `Mail Server` | Full display name shown during client setup |
| `display_short_name` | `Mail` | Short name shown in client UI |

## References

- [Mozilla Autoconfig Format](https://wiki.mozilla.org/Thunderbird:Autoconfiguration:ConfigFileFormat)
- [Microsoft Autodiscover Reference](https://learn.microsoft.com/en-us/exchange/client-developer/web-service-reference/autodiscover-web-service-reference-for-exchange)
- [Apple Configuration Profile Reference](https://developer.apple.com/business/documentation/Configuration-Profile-Reference.pdf)
