# Release Notes

## v0.1.2

### Highlights

- **`mail upgrade`**: new CLI command that gracefully updates an installation to the latest GitHub release (or `--canary` prerelease / `--version <tag>`), with binary backup, atomic swap, and service restart.
- **IMAP unread counts**: `APPEND` now honors the client flag list, so copies saved to Sent/Drafts no longer surface as unread in STATUS, webmail, or client badges.
- **Antispam suite**: content-based spam scoring with configurable thresholds and Junk foldering, decode-before-scan filter upgrade, EDNS0 DNS, persistent greylisting, DNSBL handling, and brand-spoof/outreach detection.
- **Multi-domain hosting**: per-domain isolated mailboxes, per-domain outbound DKIM signing, and multiple local-delivery domains.
- **Delivery hardening**: opportunistic STARTTLS on outbound delivery, retry/bounce fixes, and silent-delivery-loss prevention.

### Fixes

- fix(imap): honor APPEND flag list so sent/draft copies are not unread
- fix(dkim): verify all signatures and reconstruct CRLF so Stripe/SES mail passes
- fix(dkim): avoid use-after-free when reporting the signing domain
- fix(smtp): CRLF-aware header/body split + drain rejected BDAT payloads
- fix(smtp): stop sending duplicate 250 responses after DATA/BDAT
- fix(smtp): redact AUTH credentials from command logs
- fix(greylist): SPF-pass bypass + subnet-keyed triplets so provider mail delivers
- fix(delivery): harden retry bounce handling and restore release build compatibility
- fix(antispam): stop HTML_HIDDEN_TEXT over-firing on legitimate newsletters
- fix(caldav): revert line-unfolding that caused a use-after-free

Prebuilt binaries for linux & macOS (x86_64 + arm64) are attached below.

Install via pantry:

```sh
pantry install github.com/mail-os/mail
```
