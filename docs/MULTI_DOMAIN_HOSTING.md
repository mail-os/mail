# Multi-Domain Hosting

Run mailboxes for several **unrelated** domains on a single mail server instance,
each fully isolated — its own accounts, its own server hostname, its own DKIM
identity. `info@domain-a.com` and `info@domain-b.com` are different people, and
nothing leaks between them.

This is distinct from [Multi-Tenancy](MULTI_TENANCY.md), which is about billing
tiers and quota for a SaaS. Multi-domain hosting is purely about serving more
than one domain's mail from one instance.

## The three pillars

| Concern | Mechanism | Config |
|---|---|---|
| **Mailbox isolation** | Full-address username → its own maildir | `SMTP_LOCAL_DOMAINS` + full-address `username` |
| **Server identity / TLS** | One cert with every hosted mail host as a SAN | combined-SAN Let's Encrypt cert |
| **Outbound authentication** | Per-domain DKIM signer, selected by sender | `DKIM_EXTRA_KEYS` |

---

## 1. Mailbox isolation

### How it works

The maildir a message is stored under is the account's **canonical key**:

- A user whose `username` is a **full address** (`info@example.com`) is a
  *per-domain isolated mailbox*. Its maildir is `mail/info@example.com/`.
  `info@a.com` and `info@b.com` never collide.
- A user whose `username` is a **bare local-part** (`chris`) keeps the legacy
  single-namespace behaviour. Its maildir is `mail/chris/`, and it can log in /
  receive as `chris@` any hosted domain.

The decision is **per-user**, made when the account is created — there is no
global flag. Existing local-part accounts are unaffected by hosting new domains.

### Implementation

- `auth.canonicalUsername(address)` (`src/auth/auth.zig`) — resolves a login or
  recipient address to the canonical key: the full address if it is a registered
  user, else the local-part. `verifyCredentials` normalizes the same way, so a
  client may authenticate as `info@example.com` (isolated) or as `chris` /
  `chris@host` (legacy).
- **IMAP** (`src/protocol/imap.zig`) stores the canonical key on
  LOGIN/AUTHENTICATE and keys every maildir path off it.
- **SMTP delivery** (`src/core/protocol.zig`, `saveMessage`) checks
  `userExists(rcpt)`: a registered full address delivers to
  `mail/<full-address>/`; otherwise it resolves the local-part through the
  aliases file (`postmaster@`, `abuse@`, … → a real user) — the legacy path.

### Setup

1. Tell the server the domain is local (so its mail is delivered, not relayed):

   ```bash
   # /etc/mail/mail.env
   SMTP_LOCAL_DOMAINS=example.com           # comma-separate multiple domains
   ```

2. Create the isolated mailbox with the **full address** as the username:

   ```bash
   ./mail-server user:local create info@example.com '<password>' info@example.com
   ```

   (A bare-local-part account — `./mail-server user:local create chris … ` — stays
   in the shared namespace, by contrast.)

3. Restart so the new local domain takes effect:

   ```bash
   systemctl restart mail.service
   ```

### Migrating an existing local-part mailbox to an isolated one

If a mailbox already exists as a local-part (`info`) and you want to make it
isolated (`info@example.com`), rename it across all username-keyed tables and
move its maildir. The username column is `UNIQUE`; `imap_mailboxes` / `imap_uids`
carry UID continuity:

```bash
NEW=info@example.com
sqlite3 /opt/mail/smtp.db "UPDATE users           SET username='$NEW' WHERE username='info';"
sqlite3 /opt/mail/smtp.db "UPDATE imap_mailboxes  SET username='$NEW' WHERE username='info';"
sqlite3 /opt/mail/smtp.db "UPDATE imap_uids       SET username='$NEW' WHERE username='info';"
sqlite3 /opt/mail/smtp.db "UPDATE webmail_sessions SET username='$NEW' WHERE username='info';"
mv /opt/mail/mail/info "/opt/mail/mail/$NEW"
chown -R mail-server:mail-server "/opt/mail/mail/$NEW"
systemctl restart mail.service
```

The renamed account keeps its password (only the username column changes).

---

## 2. Server identity & TLS (combined-SAN cert)

The IMAP/SMTP listeners present a **single** certificate (the mail server does not
do per-connection SNI). To let clients connect to `mail.<each-domain>` without a
certificate warning, that one cert must carry **every** hosted mail hostname as a
Subject Alternative Name.

Issue one cert covering all of them and point the server at it:

```bash
# all hosted mail hostnames in one cert; the first name becomes the file base
tlsx acme:issue \
  -d "mail.a.com,autodiscover.a.com,mail.b.com,autodiscover.b.com" \
  --method http-01 --webroot /var/www/acme-challenge --dir /etc/certs --prod \
  --email admin@a.com
```

```bash
# /etc/mail/mail.env  — mail server reads this one cert for all hosts
SMTP_TLS_CERT=/etc/certs/mail.a.com.crt        # fullchain (leaf + chain)
SMTP_TLS_KEY=/etc/certs/mail.a.com.key
```

Notes:

- **`SMTP_HOSTNAME` stays global** (the EHLO greeting). Clients validate the cert
  against the hostname they connected to, *not* the greeting, so a single greeting
  hostname with a multi-SAN cert is fine.
- Each hosted mail host needs a DNS **A** record → the server, and an **MX** for
  the domain (`example.com MX → mail.example.com`).
- **Renewal preserves SANs**: `tlsx acme:renew` re-derives the domain list from
  the existing certificate's SANs, so the multi-SAN set self-perpetuates. Just
  ensure every name keeps resolving to the server (http-01) or that your DNS
  provider covers them (dns-01).
- **dns-01 caveat:** dns-01 only works for domains whose DNS your provider
  credentials manage. If the hosted domains live across different providers, use
  http-01 (every name simply needs an A record + a webroot that serves
  `/.well-known/acme-challenge/`).

See [ACME / Let's Encrypt](ACME_LETS_ENCRYPT.md) and
[TLS proxy setup](TLS_PROXY_SETUP.md).

---

## 3. Outbound DKIM (per-domain)

Outbound mail is RSA-SHA256, relaxed/relaxed DKIM-signed
(`src/antispam/dkim_sign.zig`). With multiple domains, each must sign with its
**own** key so the signature's `d=` aligns with the `From:` domain — otherwise
DMARC can only pass via SPF alignment.

A small signer registry (`src/delivery/outbound.zig`) is built once at startup
and selected per message by the **envelope sender's domain**; the first-registered
signer (the primary `DKIM_DOMAIN`) is the fallback for any domain without its own
key, preserving legacy behaviour.

### Setup for a new domain

1. Generate a key and publish the public half:

   ```bash
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /opt/mail/dkim/example.private
   chown mail-server:mail-server /opt/mail/dkim/example.private && chmod 600 /opt/mail/dkim/example.private

   # publish this TXT at  mail._domainkey.example.com
   echo "v=DKIM1; k=rsa; p=$(openssl rsa -in /opt/mail/dkim/example.private -pubout -outform DER 2>/dev/null | base64 -w0)"
   ```

2. Register the signer:

   ```bash
   # /etc/mail/mail.env  — comma-separate multiple "domain:selector:path" entries
   DKIM_EXTRA_KEYS=example.com:mail:/opt/mail/dkim/example.private
   ```

3. Restart. The startup log confirms each signer:

   ```
   Outbound DKIM signing enabled (d=example.com s=mail)
   ```

### Verify

```bash
# the private key's public half must equal the published p= record
LOCAL=$(openssl rsa -in /opt/mail/dkim/example.private -pubout -outform DER 2>/dev/null | base64 -w0)
DNS=$(dig +short TXT mail._domainkey.example.com | tr -d '" ' | sed 's/.*p=//')
[ "$LOCAL" = "$DNS" ] && echo MATCH || echo MISMATCH
```

End-to-end: from an authenticated client, send to `https://www.mail-tester.com`
or a Gmail address and confirm **DKIM=pass** with `d=example.com`, plus
**SPF=pass** and **DMARC=pass (aligned)**.

See [DKIM key rotation](DKIM_KEY_ROTATION.md).

---

## DNS checklist per hosted domain

| Record | Name | Value |
|---|---|---|
| **A** | `mail.example.com` | server IP |
| **A** | `autodiscover.example.com` | server IP (optional, for client autoconfig) |
| **MX** | `example.com` | `mail.example.com` (priority 10) |
| **TXT** (SPF) | `example.com` | `v=spf1 ip4:<server-ip> ~all` |
| **TXT** (DKIM) | `mail._domainkey.example.com` | `v=DKIM1; k=rsa; p=…` |
| **TXT** (DMARC) | `_dmarc.example.com` | `v=DMARC1; p=none; rua=mailto:…` |

If the domain has a wildcard CNAME (`*.example.com`), the explicit `mail` /
`autodiscover` **A** records override it for those names.

---

## End-to-end: add a domain in full

```bash
# 1. DNS: A mail/autodiscover → server, MX → mail.example.com, SPF, DMARC (see table)

# 2. Local delivery + isolated mailbox
echo "SMTP_LOCAL_DOMAINS=...,example.com"                                  >> /etc/mail/mail.env
./mail-server user:local create info@example.com '<pw>' info@example.com

# 3. TLS: reissue the mail cert with the new mail host as an added SAN
tlsx acme:issue -d "mail.existing.com,...,mail.example.com,autodiscover.example.com" \
  --method http-01 --webroot /var/www/acme-challenge --dir /etc/certs --prod --email admin@example.com

# 4. DKIM
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /opt/mail/dkim/example.private
# publish mail._domainkey.example.com TXT (see §3), then:
echo "DKIM_EXTRA_KEYS=...,example.com:mail:/opt/mail/dkim/example.private"  >> /etc/mail/mail.env

# 5. Apply
systemctl restart mail.service
```

## See Also

- [Configuration Guide](CONFIGURATION.md) — `SMTP_LOCAL_DOMAINS`, `DKIM_EXTRA_KEYS`, TLS vars
- [ACME / Let's Encrypt](ACME_LETS_ENCRYPT.md)
- [DKIM Key Rotation](DKIM_KEY_ROTATION.md)
- [Autoconfiguration](AUTOCONFIGURATION.md) — client autodiscover/autoconfig
- [Architecture](ARCHITECTURE.md)
