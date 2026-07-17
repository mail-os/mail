# Changelog

## [0.1.3] - 2026-08-02

- fix(cli): probe systemctl by invoking it during upgrade restart
- ci(version): run bump from packages/zig where build.zig.zon lives

## [0.1.2] - 2026-08-02

- ci: pin zig 0.16.0 across workflows and add release notes
- feat(cli): add upgrade command for GitHub release updates
- chore(imap): log STATUS responses for unread-count diagnostics
- fix(imap): honor APPEND flag list so sent/draft copies are not unread
- fix(delivery): restore release build compatibility
- fix(delivery): harden retry bounce handling
- fix(smtp): prevent silent delivery loss
- feat(antispam): harden inbound spam detection
- chore: refresh pantry lockfile
- docs: add repository agent guidance
- fix(antispam): stop HTML_HIDDEN_TEXT over-firing on legitimate newsletters
- fix(dkim): avoid use-after-free when reporting the signing domain
- fix(dkim): verify all signatures and reconstruct CRLF so Stripe/SES mail passes
- fix(antispam): stop foldering authenticated transactional mail into Junk
- fix(smtp): don't emit a stray 250 after rejecting a message as spam
- feat(antispam): decode-before-scan filter upgrade, EDNS0 DNS, persistent greylist
- fix(smtp): CRLF-aware header/body split + drain rejected BDAT payloads
- fix(greylist): SPF-pass bypass + subnet-keyed triplets so provider mail delivers
- fix(smtp): deliver auto-forwards to local-domain isolated mailboxes
- feat(antispam): score unsolicited SEO/web-design outreach and brand-spoof phishing
- docs(smtp): document spam-filter and DNSBL options
- feat(smtp): score inbound mail and file spam into Junk
- feat(smtp): add spam-filter config (thresholds, Junk folder, DNSBL reject)
- feat(smtp): add content-based spam scoring module
- fix(smtp): treat DNSBL 127.255.255.0/24 answers as errors, not listings
- fix(smtp): injected Message-ID uses the From domain, not the hostname
- fix(smtp): AUTH fails closed when no auth backend is configured
- fix(smtp): sign a synthesized From header for DMARC alignment
- feat(smtp): inject a Date header on submissions missing one
- refactor(smtp): share the RFC 5322 date formatter via time_compat
- fix(smtp): stop sending a duplicate 250 after DATA/BDAT
- feat(smtp): opportunistic STARTTLS on outbound delivery
- fix(smtp): redact AUTH credentials from command logs
- docs(mail): document multi-domain hosting (isolated mailboxes, combined-SAN TLS, per-domain DKIM)
- feat(mail): per-domain outbound DKIM signing
- feat(mail): per-domain isolated mailboxes (full-address as canonical key)
- Add native build + hot-swap deploy script for linux hosts
- feat(smtp): support multiple local-delivery domains
- feat(cloud): resolve mail hostname over loopback during provisioning
- chore(config): move stx.config.ts to config/stx.ts
- fix(caldav): revert line-unfolding — it caused a use-after-free
- polish(caldav): parse ICS ORGANIZER (mailto: stripped)
- polish(caldav): typed vCard emails/phones, line unfolding, more fields
- feat(mta-sts): configurable policy mode, default enforce
- fix(caldav): persist structured event/contact fields on PUT
- feat(antispam): policy-aware DMARC enforcement + client IP in auth-failure logs
- feat(antispam,secrets): DKIM d= alignment, IPv6 DNSBL + SPF, cloud secret backends
- feat(delivery): aliases-file resolution for role mailboxes
- feat(search): COPY/MOVE index sync + webmail search endpoint
- feat(delivery): retry pipeline + DSN bounces for failed outbound mail
- feat(imap): indexed SEARCH + inotify-based IDLE push
- feat(search): Typesense full-text search via zig-search-engine
- ci(docker): pre-render the webmail bundle before the image build
- build: make the webmail frontend step actually best-effort
- ci(docker): bun needs libgcc/libstdc++ on Alpine
- ci(docker): zig mirror fallback + bun in the builder image
- ci: install bun for the webmail build step; zig fmt
- chore: remove dead infrastructure modules
- fix(features): GDPR export, POP3 maildrop lock, quota recalc, autoresponder, session sweep
- perf(observability): non-blocking Discord posts, alloc-free metric names
- perf(net): TCP keepalive, poll()-based accept loops, SMTP read timeouts, CalDAV plaintext keep-alive
- perf(auth): cache verified logins; fix rate-limiter UAF + unbounded growth
- perf(delivery): in-process MX lookups, O(1) queue ops, real bounce dates
- perf(antispam): process-wide DNS TTL cache; honest ARC verdict
- perf(imap): bulk UID sync, UID->seq index, cheap IDLE polling
- fix(db): checked binds, foreign_keys, transactional UID ops; drop dead dbstorage
- perf(logger): format log lines outside the mutex
- perf(smtp): buffered socket reads + reuse startup-parsed TLS cert

All notable changes to this project will be documented in this file.

