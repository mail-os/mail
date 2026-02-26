# DANE / TLSA

DNS-Based Authentication of Named Entities (DANE) for SMTP, providing certificate pinning via DNSSEC-secured TLSA DNS records.

## Purpose

Traditional TLS for SMTP relies on the public CA infrastructure (PKIX) for certificate validation. DANE eliminates the need to trust hundreds of CAs by allowing domain owners to publish the exact certificate or public key that a connecting MTA should expect, directly in DNS. When protected by DNSSEC, this creates an end-to-end authenticated binding between the domain name and the TLS certificate.

## Relevant RFCs

- **RFC 6698** -- The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA
- **RFC 7672** -- SMTP Security via Opportunistic DANE TLS
- **RFC 7671** -- The DNS-Based Authentication of Named Entities (DANE) Protocol: Updates and Operational Guidance

## Configuration

### Environment Variables

```bash
SMTP_ENABLE_DANE=true
```

### TOML Configuration

```toml
[dane]
enabled = true
```

## TLSA Record Format

TLSA records are published at `_<port>._tcp.<hostname>` and contain four fields:

```
_25._tcp.mail.example.com. IN TLSA <usage> <selector> <matching_type> <data>
```

### Certificate Usage (Field 1)

| Value | Name      | Description                                                    |
|-------|-----------|----------------------------------------------------------------|
| 0     | PKIX-TA   | CA constraint -- must chain to a CA matching the record        |
| 1     | PKIX-EE   | Service cert constraint -- end-entity must match + PKIX valid  |
| 2     | DANE-TA   | Trust anchor assertion -- chain must include matching anchor   |
| 3     | DANE-EE   | Domain-issued cert -- end-entity must match directly           |

**DANE-EE (usage 3)** is recommended for SMTP per RFC 7672 Section 3.1, as it avoids PKIX complexity and does not require hostname verification.

### Selector (Field 2)

| Value | Name                  | Description                         |
|-------|-----------------------|-------------------------------------|
| 0     | Full certificate      | Match against the DER-encoded cert  |
| 1     | SubjectPublicKeyInfo  | Match against the DER-encoded SPKI  |

### Matching Type (Field 3)

| Value | Name   | Description                 |
|-------|--------|-----------------------------|
| 0     | Exact  | No hashing, exact DER match |
| 1     | SHA-256| SHA-256 hash of the data    |
| 2     | SHA-512| SHA-512 hash of the data    |

## DNS Record Examples

```dns
; DANE-EE with SHA-256 of SubjectPublicKeyInfo (recommended)
_25._tcp.mail.example.com. IN TLSA 3 1 1 (
    2b7e1f3a8c9d0e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f )

; DANE-TA with SHA-256 of the CA certificate
_25._tcp.mail.example.com. IN TLSA 2 0 1 (
    a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2 )
```

## How It Works with SMTP

When delivering mail to `user@example.com`:

1. **MX Lookup** -- Resolve MX records for `example.com` to find `mail.example.com`.
2. **TLSA Lookup** -- Query `_25._tcp.mail.example.com` for TLSA records, requiring DNSSEC validation.
3. **Evaluate DNSSEC status**:
   - **Secure (AD flag set)** -- TLSA records are trusted. TLS is mandatory; the presented certificate must match.
   - **Insecure (no DNSSEC)** -- TLSA records are ignored. Fall back to opportunistic TLS.
   - **Bogus (DNSSEC failure)** -- Treat as a temporary error; do not deliver.
4. **TLS Handshake** -- Connect to the MX host, perform STARTTLS, and validate the certificate against the TLSA record.
5. **Result** -- If the certificate matches, delivery proceeds. If not, the connection is aborted (no fallback to plaintext).

## Validation Results

| Result      | Meaning                                                |
|-------------|--------------------------------------------------------|
| `pass`      | Certificate matches a TLSA record                      |
| `fail`      | Certificate does not match any TLSA record             |
| `temperror` | DNS timeout or transient DNSSEC failure                |
| `permerror` | Malformed TLSA record or permanent DNSSEC failure      |
| `none`      | No TLSA records found (DANE not configured)            |

## Generating TLSA Records

```bash
# Generate a DANE-EE (3 1 1) record from a certificate
openssl x509 -in cert.pem -noout -pubkey \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -hex \
  | awk '{print "3 1 1 " $NF}'

# Generate from a private key
openssl pkey -in key.pem -pubout -outform DER \
  | openssl dgst -sha256 -hex \
  | awk '{print "3 1 1 " $NF}'
```

## Security Considerations

- DANE provides no security benefit without DNSSEC. Ensure your zone is signed.
- Usage 3 (DANE-EE) is preferred for SMTP because it is self-contained and does not depend on external CAs.
- Always cache TLSA records respecting their DNS TTL.
- Handle DNS timeouts gracefully -- return `temperror` and retry later rather than delivering without verification.
- When rotating certificates, publish the new TLSA record before installing the new cert, and remove the old record only after the old cert is no longer in use.

## See Also

- [TLS Reporting (TLS-RPT)](TLS_RPT.md) -- reports DANE validation failures
- [MTA-STS](MTA_STS.md) -- complementary TLS enforcement mechanism
- [Configuration Guide](CONFIGURATION.md)
- Source: `src/antispam/dane.zig`
