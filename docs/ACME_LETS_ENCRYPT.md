# ACME / Let's Encrypt

Automatic TLS certificate provisioning and renewal using the ACME protocol (RFC 8555), compatible with Let's Encrypt and other ACME certificate authorities.

## Purpose

Manually managing TLS certificates for a mail server is error-prone -- expired certificates cause mail delivery failures. The ACME integration automates the entire certificate lifecycle: account creation, domain validation, certificate issuance, installation, and renewal. This ensures the server always has a valid TLS certificate without operator intervention.

## Relevant RFCs

- **RFC 8555** -- Automatic Certificate Management Environment (ACME)
- **RFC 7638** -- JSON Web Key (JWK) Thumbprint (used in challenge responses)

## Configuration

### Environment Variables

```bash
# Enable ACME auto-provisioning
SMTP_ENABLE_ACME=true

# Contact email for the ACME account (required by Let's Encrypt)
SMTP_ACME_EMAIL=admin@example.com
```

### TOML Configuration

```toml
[acme]
enabled = true
email = "admin@example.com"
```

### Full Configuration Options

```zig
var config = ACMEConfig{
    .directory_url = ACMEConfig.LETS_ENCRYPT_PRODUCTION,
    .email = "admin@example.com",
    .domains = &.{ "mail.example.com", "smtp.example.com" },
    .key_type = .ec256,
    .auto_renew = true,
    .renew_before_days = 30,
    .cert_dir = "/etc/ssl/acme",
};
```

## ACME Protocol Flow

```
1. GET  /directory                    -> discover endpoints
2. POST /acme/new-account             -> register/find account
3. POST /acme/new-order               -> submit certificate order
4. POST /acme/authz/{id}              -> fetch challenge details
5. Provision challenge response        (HTTP-01, DNS-01, or TLS-ALPN-01)
6. POST /acme/challenge/{id}          -> notify CA challenge is ready
7. Poll /acme/order/{id}              -> wait for status: "ready"
8. POST /acme/order/{id}/finalize     -> submit CSR
9. POST /acme/cert/{id}              -> download PEM certificate chain
```

## Challenge Types

| Type          | Method                                                  |
|---------------|---------------------------------------------------------|
| `http-01`     | Serve `<token>.<thumbprint>` at `/.well-known/acme-challenge/<token>` |
| `dns-01`      | Create TXT record at `_acme-challenge.<domain>`         |
| `tls-alpn-01` | Serve special TLS cert with `acme-tls/1` ALPN extension|

HTTP-01 is the primary method. The thumbprint is the base64url-encoded SHA-256 hash of the account key's JWK thumbprint (RFC 7638). The challenge proves domain control because only the web server operator can serve the correct response.

## Certificate Renewal

The renewal strategy follows this timeline:

```
|--issued--|----------valid----------|--renew--|--expire--|
                                      ^
                              renew_before_days (default: 30)
```

- **Check interval**: Every 12 hours.
- **Renewal window**: 30 days before expiry (configurable via `renew_before_days`).
- **Retry on failure**: Exponential backoff -- 1h, 2h, 4h, 8h, max 24h.
- **Background thread**: `CertRenewalThread` runs continuously and monitors all managed certificates.

## Key Types

| Key Type  | Description                  | Recommendation              |
|-----------|------------------------------|-----------------------------|
| `ec256`   | ECDSA P-256                  | Recommended (smaller keys)  |
| `ec384`   | ECDSA P-384                  | Higher security             |
| `rsa2048` | RSA 2048-bit                 | Broad compatibility         |
| `rsa4096` | RSA 4096-bit                 | Maximum RSA security        |

## Certificate Paths

Certificates and keys are stored under the configured `cert_dir`:

```
/etc/ssl/acme/
  mail.example.com/
    cert.pem          # Full certificate chain
    privkey.pem       # Private key (mode 0600)
    chain.pem         # Intermediate certificates
    account.key       # ACME account key (mode 0600)
```

## Staging vs Production

| Environment | Directory URL                                          | Rate Limits    |
|-------------|--------------------------------------------------------|----------------|
| Staging     | `https://acme-staging-v02.api.letsencrypt.org/directory` | Relaxed        |
| Production  | `https://acme-v02.api.letsencrypt.org/directory`         | 50 certs/week  |

Always test with the staging environment first. Staging certificates are not trusted by browsers or mail clients but the flow is identical.

## Security Considerations

- Account private keys are stored with restrictive permissions (0600).
- Challenge tokens are validated before being served.
- ACME nonces are consumed exactly once (replay protection).
- All ACME requests use JWS (JSON Web Signature) with ES256 or RS256.

## See Also

- [TLS Proxy Setup](TLS_PROXY_SETUP.md)
- [Configuration Guide](CONFIGURATION.md)
- [Security Guide](SECURITY_GUIDE.md)
- Source: `src/security/acme.zig`
