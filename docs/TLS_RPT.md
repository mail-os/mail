# TLS Reporting (TLS-RPT)

SMTP TLS Reporting (RFC 8460) for aggregating and sending reports about TLS connection failures encountered during mail delivery.

## Purpose

When sending MTAs enforce TLS policies (via MTA-STS or DANE), connection failures can silently prevent mail delivery. TLS-RPT provides a feedback mechanism: the sending MTA records successes and failures, then periodically sends aggregate JSON reports to the receiving domain's designated reporting address. This allows domain operators to detect misconfigurations, expired certificates, and STARTTLS stripping attacks.

## Relevant RFCs

- **RFC 8460** -- SMTP TLS Reporting
- **RFC 8461** -- SMTP MTA Strict Transport Security (MTA-STS)
- **RFC 7672** -- SMTP Security via Opportunistic DANE TLS

## Configuration

### Environment Variables

```bash
SMTP_ENABLE_TLS_RPT=true
```

### TOML Configuration

```toml
[tls_rpt]
enabled = true
```

## DNS Record Format

The receiving domain publishes a TXT record at `_smtp._tls.<domain>`:

```dns
_smtp._tls.example.com. IN TXT "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
```

| Field | Description                                                             |
|-------|-------------------------------------------------------------------------|
| `v`   | Version string. Must be `TLSRPTv1`.                                    |
| `rua` | Reporting URI(s). Comma-separated `mailto:` or `https:` addresses.     |

### Multiple Reporting Destinations

```dns
_smtp._tls.example.com. IN TXT "v=TLSRPTv1; rua=mailto:reports@example.com,https://tlsrpt.example.com/report"
```

Reports sent to `mailto:` addresses are delivered as gzip-compressed JSON attachments. Reports sent to `https:` endpoints are POSTed as JSON.

## JSON Report Schema

Reports follow the structure defined in RFC 8460 Section 4:

```json
{
  "organization-name": "Example Mail Server",
  "date-range": { "start-datetime": "1706140800", "end-datetime": "1706227200" },
  "contact-info": "postmaster@sender.example.com",
  "report-id": "1706227200-example.com",
  "policies": [{
    "policy": {
      "policy-type": "sts",
      "policy-string": ["version: STSv1", "mode: enforce", "mx: mail.example.com"],
      "policy-domain": "example.com",
      "mx-host": "mail.example.com"
    },
    "summary": { "total-successful-session-count": 4523, "total-failure-session-count": 3 },
    "failure-details": [{
      "result-type": "certificate-expired",
      "receiving-mx-hostname": "mail.example.com",
      "failed-session-count": 3
    }]
  }]
}
```

## Failure Types

The server tracks these TLS failure categories per RFC 8460 Section 4.3:

| Failure Type                       | Description                                       |
|------------------------------------|---------------------------------------------------|
| `starttls-not-supported`           | Remote server did not advertise STARTTLS           |
| `certificate-invalid`              | Certificate failed validation                     |
| `certificate-expired`              | Certificate has expired                            |
| `certificate-hostname-mismatch`    | Certificate CN/SAN does not match hostname         |
| `policy-mismatch`                  | MX not listed in MTA-STS policy                   |
| `sts-policy-invalid`               | MTA-STS policy could not be parsed                 |
| `dane-required`                    | DANE TLSA record requires TLS but it failed        |

## Result Types (failure-details)

| Result Type               | Description                                |
|---------------------------|--------------------------------------------|
| `starttls-not-supported`  | No STARTTLS offered                        |
| `certificate-host-mismatch` | Hostname verification failed             |
| `certificate-expired`     | Certificate past validity period           |
| `certificate-not-trusted` | Certificate chain not trusted              |
| `validation-failure`      | General TLS validation failure             |
| `tlsa-invalid`            | DANE TLSA record is malformed              |
| `dnssec-invalid`          | DNSSEC validation failed                   |
| `dane-required`           | DANE requires TLS but connection failed    |
| `sts-policy-fetch-error`  | Could not fetch MTA-STS policy             |
| `sts-policy-invalid`      | MTA-STS policy is malformed                |
| `sts-webpki-invalid`      | MTA-STS HTTPS certificate invalid          |
| `negotiation-failure`     | TLS handshake failed                       |

## Policy Types

| Type               | Description                      |
|--------------------|----------------------------------|
| `tlsa`             | DANE/TLSA policy in effect       |
| `sts`              | MTA-STS policy in effect         |
| `no-policy-found`  | No TLS policy found for domain   |

## Aggregation

The `TLSReportAggregator` collects statistics in a thread-safe manner:

- `recordSuccess(domain, mx)` -- Increment successful session count.
- `recordFailure(domain, mx, type, detail)` -- Increment failure count; identical type+detail pairs are coalesced.
- `generateReport(domain)` -- Produce RFC 8460 JSON for a specific domain.
- `getStats()` -- Return aggregate statistics across all tracked domains.

Reports are generated and sent once every 24 hours.

## Deployment

1. Enable TLS-RPT in the server configuration.
2. Publish a `_smtp._tls.<domain>` TXT record for each domain you want to receive reports about.
3. Set up a mailbox or HTTPS endpoint to receive reports.
4. Monitor incoming reports for unexpected failures.

```bash
# Verify your TLS-RPT record
dig TXT _smtp._tls.example.com +short
# Expected: "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
```

## See Also

- [MTA-STS](MTA_STS.md) -- the TLS policy mechanism that TLS-RPT reports on
- [DANE / TLSA](DANE.md) -- DNSSEC-based TLS authentication (also reported by TLS-RPT)
- [Configuration Guide](CONFIGURATION.md)
- Source: `src/delivery/tls_rpt.zig`
