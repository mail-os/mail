# BIMI - Brand Indicators for Message Identification

**Source:** `src/antispam/bimi.zig`

## Overview

BIMI (Brand Indicators for Message Identification) allows domain owners to display
their brand logo alongside authenticated email messages in supporting mail clients.
When a receiving server confirms that a message passes DMARC with a policy of
`quarantine` or `reject`, it looks up the sender's BIMI DNS record and retrieves
the brand indicator (an SVG image) for display to the recipient.

## How BIMI Works

1. The sender publishes a BIMI DNS TXT record at `default._bimi.<domain>`
2. The receiving server verifies DMARC alignment (must pass with `p=quarantine` or `p=reject`)
3. The server queries the BIMI DNS record for the sender's domain
4. If a valid record is found, the server fetches the SVG indicator
5. Optionally, the server validates the VMC (Verified Mark Certificate)
6. The brand logo is displayed to the recipient in supporting mail clients

## DNS Record Format

BIMI records are published as DNS TXT records at `default._bimi.<domain>`:

```
default._bimi.example.com. IN TXT "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"
```

### Record Tags

| Tag | Required | Description |
|-----|----------|-------------|
| `v=` | Yes | Version string; must be `BIMI1` |
| `l=` | Yes | HTTPS URL pointing to an SVG Tiny PS brand indicator image |
| `a=` | No | HTTPS URL pointing to a VMC (Verified Mark Certificate) in PEM format |

### SVG Requirements

The logo must conform to **SVG Tiny PS** (Portable/Secure) profile:

- Must be square
- No scripts, animations, or external references
- File must be served over HTTPS

### VMC (Verified Mark Certificate)

A VMC is an S/MIME certificate issued by a recognized Mark Verifying Authority (MVA)
that cryptographically binds the brand logo to the domain. While optional, a VMC is
required by major mailbox providers (Gmail, Apple Mail) to actually display the logo.

## DMARC Alignment Requirement

BIMI **requires** a DMARC policy of `p=quarantine` or `p=reject`. Domains with
`p=none` are not eligible for BIMI. The DMARC record must also have proper SPF
and/or DKIM alignment.

```
_dmarc.example.com. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
```

## BIMI Evaluation Results

```
pass      - BIMI record found and validated; indicator may be displayed
none      - No BIMI record published for the domain
fail      - Evaluation failed (invalid record, DMARC not met, etc.)
temperror - Temporary error during lookup (DNS timeout, fetch failure)
decline   - Record found but receiver chose not to display it
```

## Configuration

Enable BIMI via environment variable:

```bash
SMTP_ENABLE_BIMI=true
```

Or in a configuration file under the `[bimi]` section:

```ini
[bimi]
enabled = true
```

When enabled, the server will:

1. Check that the message passes DMARC with `p=quarantine` or `p=reject`
2. Query the `default._bimi.<domain>` DNS TXT record
3. Parse and validate the BIMI record tags
4. Fetch and validate the SVG indicator (and VMC if present)
5. Add a `BIMI-Location` or `BIMI-Indicator` header with the result

## Example DNS Lookup

```bash
dig TXT default._bimi.example.com
# "v=BIMI1; l=https://example.com/brand/logo.svg; a=https://example.com/brand/vmc.pem"
```

## References

- [BIMI Working Group - Brand Indicators for Message Identification](https://bimigroup.org/)
- [RFC 7489 - Domain-based Message Authentication, Reporting, and Conformance (DMARC)](https://datatracker.ietf.org/doc/html/rfc7489)
- [AuthIndicators BIMI Specification](https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/)
