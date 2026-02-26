# ARC - Authenticated Received Chain

**RFC:** 8617
**Source:** `src/antispam/arc.zig`

## Overview

ARC (Authenticated Received Chain) preserves email authentication results across
intermediaries such as mailing lists and forwarding services. When a message passes
through a forwarder, SPF and DKIM often break because the envelope sender or message
body changes. ARC records the authentication state at each hop so the final receiver
can evaluate the full chain of custody rather than relying solely on the last hop.

## How ARC Works

Each intermediary that handles a message adds an **ARC set** consisting of three
headers, all sharing the same instance number (`i=`):

| Header | Abbreviation | Purpose |
|--------|-------------|---------|
| `ARC-Authentication-Results` | AAR | Records SPF, DKIM, and DMARC results observed at this hop |
| `ARC-Message-Signature` | AMS | DKIM-like signature over the message headers and body |
| `ARC-Seal` | AS | Signature over all previous ARC sets plus the current AAR and AMS |

### Instance Numbering

Instance numbers start at `i=1` for the first intermediary and increment by one at
each subsequent hop. A receiver validates the chain by walking from `i=1` up to the
highest instance.

### Chain Validation (`cv=` tag)

The ARC-Seal header contains a `cv=` (chain validation) tag indicating the state of
all previous ARC sets at the time this set was created:

| Value | Meaning |
|-------|---------|
| `cv=none` | This is the first ARC set in the chain (i=1) |
| `cv=pass` | All previous ARC sets validated successfully |
| `cv=fail` | One or more previous ARC sets failed validation |

If any seal in the chain has `cv=fail`, the entire chain is considered invalid.

## Relationship to DKIM

ARC reuses DKIM's signing infrastructure (RSA/Ed25519 keys, DNS `_domainkey` records,
canonicalization algorithms). The AMS header uses the same format as a DKIM-Signature.
The critical difference is that ARC captures the authentication state at each hop,
whereas DKIM only covers the originating domain's signature.

## ARC Validation Results

The implementation produces one of these results:

```
pass      - Valid chain; all seals and signatures verified
fail      - Chain broken; at least one seal or signature invalid
none      - No ARC sets present on the message
temperror - Temporary failure during validation (e.g., DNS timeout)
permerror - Permanent error (e.g., malformed headers)
```

## Configuration

Enable ARC via environment variable:

```bash
SMTP_ENABLE_ARC=true
```

Or in a configuration file under the `[arc]` section:

```ini
[arc]
enabled = true
```

When enabled, the server will:

1. **Validate** incoming ARC chains on received messages
2. **Seal** outgoing forwarded messages with a new ARC set using the server's DKIM key
3. Record ARC results in the `Authentication-Results` header

## Example ARC Headers

```
ARC-Authentication-Results: i=1; mx.example.com;
    dkim=pass header.d=sender.com;
    spf=pass smtp.mailfrom=sender.com
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed;
    d=example.com; s=arc; h=from:to:subject:date;
    bh=base64hash; b=base64sig
ARC-Seal: i=1; a=rsa-sha256; cv=none;
    d=example.com; s=arc;
    b=base64sig
```

## References

- [RFC 8617 - The Authenticated Received Chain (ARC) Protocol](https://datatracker.ietf.org/doc/html/rfc8617)
- [RFC 6376 - DomainKeys Identified Mail (DKIM) Signatures](https://datatracker.ietf.org/doc/html/rfc6376)
- [RFC 7601 - Message Header Field for Indicating Message Authentication Status](https://datatracker.ietf.org/doc/html/rfc7601)
