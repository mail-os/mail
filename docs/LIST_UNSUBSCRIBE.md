# List-Unsubscribe - RFC 8058 One-Click Unsubscribe

**RFC:** 8058, 2369
**Source:** `src/features/list_unsubscribe.zig`

## Overview

RFC 8058 defines one-click unsubscribe functionality for mailing lists. Since
February 2024, Gmail and Yahoo require bulk senders (5,000+ messages/day) to
include compliant List-Unsubscribe headers. Messages without these headers face
increased spam classification and delivery failures.

## Required Headers

Two headers must be present on every bulk/marketing message:

```
List-Unsubscribe: <https://mail.example.com/unsubscribe?token=abc123>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
```

The `List-Unsubscribe` header contains an HTTPS URL (and optionally a `mailto:`
fallback for older clients). The `List-Unsubscribe-Post` header signals that the
URL supports RFC 8058 one-click via HTTP POST.

## HTTPS Endpoint Requirements

The unsubscribe endpoint must:

1. Accept **POST requests only** (GET must not trigger unsubscription)
2. Expect `Content-Type: application/x-www-form-urlencoded`
3. Expect body: `List-Unsubscribe=One-Click`
4. Return HTTP 200 on success
5. Use HTTPS (plain HTTP is not acceptable in production)

## HMAC Token Security

Unsubscribe URLs contain an HMAC-SHA256 signed token that encodes:

| Field | Purpose |
|-------|---------|
| `list_id` | The mailing list identifier |
| `recipient` | The subscriber email address |
| `message_id` | The originating Message-ID |
| `timestamp` | Token issuance time for expiry enforcement |

Token fields are joined with a null-byte separator (`0x00`) before HMAC
computation. This prevents forgery, replay attacks, and unauthorized
unsubscriptions. Tokens have a configurable TTL (default: 30 days, maximum: 365
days).

## Configuration

### Environment Variables

```bash
SMTP_ENABLE_LIST_UNSUBSCRIBE=true
SMTP_LIST_UNSUBSCRIBE_URL=https://mail.example.com/unsubscribe
```

### Configuration File

```ini
[list_unsubscribe]
enabled = true
```

### Programmatic Configuration

```zig
const config = ListUnsubscribeConfig{
    .enabled = true,
    .url_base = "https://mail.example.com/unsubscribe",
    .require_https = true,
    .include_mailto = false,
    .mailto_address = null,
    .hmac_secret = "your-secret-key-at-least-16-bytes",
    .token_ttl_seconds = 30 * 24 * 60 * 60, // 30 days
};
```

### Configuration Fields

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Inject List-Unsubscribe headers into outgoing messages |
| `url_base` | required | Base HTTPS URL for unsubscribe endpoints |
| `require_https` | `true` | Enforce HTTPS scheme (disable only for testing) |
| `include_mailto` | `false` | Include a `mailto:` alternative for older clients |
| `mailto_address` | `null` | Address for mailto alternative (e.g., `unsubscribe@example.com`) |
| `hmac_secret` | required | Shared secret for HMAC-SHA256 signing (min 16 bytes) |
| `token_ttl_seconds` | 2592000 | Token validity duration (default 30 days) |

## Processing Flow

1. On outgoing bulk messages, the server generates an HMAC token
2. The token is embedded in the unsubscribe URL as a query parameter
3. Both `List-Unsubscribe` and `List-Unsubscribe-Post` headers are injected
4. When a recipient clicks unsubscribe, the mail client sends a POST request
5. The server validates the HMAC token and TTL
6. On success, the recipient is removed from the mailing list

## References

- [RFC 8058 - Signaling One-Click Functionality for List-Unsubscribe](https://datatracker.ietf.org/doc/html/rfc8058)
- [RFC 2369 - The Use of URLs as Meta-Syntax for Core Mail List Commands](https://datatracker.ietf.org/doc/html/rfc2369)
- [Google Bulk Sender Guidelines](https://support.google.com/mail/answer/81126)
- [Yahoo Sender Requirements](https://senders.yahooinc.com/best-practices/)
