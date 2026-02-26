# MTA-STS

Mail Transfer Agent Strict Transport Security (RFC 8461) for enforcing TLS on inbound SMTP connections via HTTPS-hosted policy files.

## Purpose

MTA-STS allows a receiving domain to declare that it supports TLS for SMTP and to specify which MX hostnames are authorized. Unlike DANE (which requires DNSSEC), MTA-STS relies on the Web PKI -- a domain publishes a policy file over HTTPS and a DNS TXT record that signals senders to fetch and enforce the policy. This prevents STARTTLS stripping attacks and MX spoofing without requiring DNSSEC deployment.

## Relevant RFCs

- **RFC 8461** -- SMTP MTA Strict Transport Security (MTA-STS)
- **RFC 8460** -- SMTP TLS Reporting (companion reporting mechanism)

## Configuration

### Environment Variables

```bash
SMTP_ENABLE_MTA_STS=true
```

### TOML Configuration

```toml
[mta_sts]
enabled = true
```

## How It Works

1. **DNS TXT Record** -- The sending MTA queries `_mta-sts.<domain>` for a TXT record.
2. **Policy Fetch** -- If the TXT record exists and is valid, the sender fetches the policy from `https://mta-sts.<domain>/.well-known/mta-sts.txt`.
3. **MX Validation** -- The sender checks that the receiving MX hostname matches one of the policy's `mx:` patterns.
4. **TLS Enforcement** -- Based on the policy mode, the sender either enforces TLS (`enforce`), reports failures only (`testing`), or takes no action (`none`).

## DNS TXT Record

Publish a TXT record at `_mta-sts.<domain>`:

```dns
_mta-sts.example.com. IN TXT "v=STSv1; id=20240101T000000"
```

| Field | Description                                                        |
|-------|--------------------------------------------------------------------|
| `v`   | Version string. Must be `STSv1`.                                   |
| `id`  | Policy identifier. Change this value whenever the policy changes.  |

The `id` field tells senders when to re-fetch the policy. Use a timestamp or incrementing value.

## Policy File Format

Host the policy at `https://mta-sts.<domain>/.well-known/mta-sts.txt`:

```
version: STSv1
mode: enforce
mx: mail.example.com
mx: *.example.com
max_age: 86400
```

| Field     | Description                                                     |
|-----------|-----------------------------------------------------------------|
| `version` | Must be `STSv1`.                                                |
| `mode`    | Policy mode: `enforce`, `testing`, or `none`.                   |
| `mx`      | Authorized MX hostname pattern. May use wildcard prefix `*.`.   |
| `max_age` | Policy cache lifetime in seconds (max 31557600 = ~1 year).      |

## Policy Modes

| Mode      | Behavior                                                              |
|-----------|-----------------------------------------------------------------------|
| `enforce` | Sending MTA **must not** deliver without valid TLS to a matching MX.  |
| `testing` | Deliver normally but report failures via TLS-RPT.                     |
| `none`    | Domain does not implement MTA-STS (used to withdraw a previous policy). |

## MX Pattern Matching

MX patterns in the policy use these rules:

- **Exact match** -- `mail.example.com` matches only `mail.example.com` (case-insensitive).
- **Wildcard match** -- `*.example.com` matches exactly one DNS label prefix (e.g., `mx1.example.com` matches, but `sub.mx1.example.com` and `example.com` do not).

## Deployment Checklist

1. Ensure all MX hosts support TLS with valid certificates from a trusted CA.
2. Serve the policy file over HTTPS at `https://mta-sts.<domain>/.well-known/mta-sts.txt`.
3. Publish the `_mta-sts.<domain>` TXT record.
4. Start in `testing` mode and monitor TLS-RPT reports for failures.
5. Once stable, switch to `enforce` mode and update the `id` in the DNS record.
6. Set up a TLS-RPT DNS record so senders can report failures (see [TLS_RPT.md](TLS_RPT.md)).

## Policy Cache

The server caches MTA-STS policies keyed by domain with TTL based on `max_age`. The cache:

- Returns only non-expired policies from `get()`.
- Provides `getEvenIfExpired()` for stale-while-revalidate patterns.
- Detects policy updates by comparing the DNS `id` field via `isPolicyUpdated()`.
- Automatically evicts expired entries when the cache reaches capacity.
- Tracks statistics per mode (`enforce`, `testing`, `none`).

## Validation Results

| Result               | Behavior                                              |
|----------------------|-------------------------------------------------------|
| `pass`               | MX matches policy; TLS validated. Deliver.            |
| `fail`               | MX does not match or TLS invalid. Block if enforcing. |
| `no_policy`          | No MTA-STS policy found. Deliver normally.            |
| `policy_fetch_error` | Could not fetch policy via HTTPS. Deliver.            |
| `temperror`          | Transient DNS error. Deliver.                         |

In `enforce` mode, only `fail` blocks delivery. All other results permit delivery.

## See Also

- [TLS Reporting (TLS-RPT)](TLS_RPT.md) -- report delivery of MTA-STS policy failures
- [DANE / TLSA](DANE.md) -- complementary DNSSEC-based TLS authentication
- [Configuration Guide](CONFIGURATION.md)
- Source: `src/antispam/mta_sts.zig`
