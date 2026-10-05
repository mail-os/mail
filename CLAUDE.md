# Mail Server

A performant, self-hosted mail server written in Zig. Supports SMTP, IMAP, POP3, CalDAV/CardDAV, and more.

## Project Structure

```
mail/
├── packages/
│   ├── zig/          # Core mail server (Zig 0.16.0-dev)
│   │   ├── src/
│   │   │   ├── main.zig              # Server entry point
│   │   │   ├── mail_cli.zig          # CLI entry point (zig-cli)
│   │   │   ├── core/                 # Core: config, logging, protocol, TLS, sockets
│   │   │   ├── protocol/             # IMAP, POP3, CalDAV, ActiveSync, etc.
│   │   │   ├── auth/                 # Auth, password hashing (Argon2id), CSRF
│   │   │   ├── storage/              # SQLite database layer
│   │   │   ├── delivery/             # Queue, bounce handling, TLS-RPT
│   │   │   ├── antispam/             # DKIM, SPF, DMARC, ARC, DNSBL
│   │   │   ├── observability/        # Logging, metrics, tracing, Discord alerts
│   │   │   ├── features/             # Sieve, quotas, templates, autoresponder
│   │   │   ├── infrastructure/       # Clustering, io_uring, connection pooling
│   │   │   └── api/                  # REST API, health checks
│   │   ├── build.zig
│   │   └── pantry/                   # Zig dependencies (zig-tls, zig-cli)
│   ├── cloud/        # AWS infrastructure (ts-cloud / CloudFormation)
│   │   └── cloud.config.ts           # EC2, SES, Route53, IAM config
│   └── ts/           # TypeScript SDK (ts-mail)
├── pantry.jsonc       # Monorepo config (workspaces, scripts)
└── docs/              # Architecture, security, protocol docs
```

## Build & Development

```bash
# Package manager is `pantry` (like npm/bun)
pantry run build          # ReleaseFast build
pantry run build:debug    # Debug build
pantry run dev            # Build + run server locally
pantry run test           # Run all tests
pantry run fmt            # Format Zig source

# Or directly from packages/zig:
cd packages/zig
zig build                         # Debug build
zig build -Doptimize=ReleaseFast  # Release build
zig build -Dtarget=x86_64-linux   # Cross-compile for Linux
zig build test                    # Run tests
zig build run -- serve            # Run server
```

## Releasing

`better-dx` supplies the dev tooling (bumpx, logsmith, pickier, gitlint) — run
`bun install` once at the repo root.

```bash
pantry run release:patch   # or release:minor, release:major
pantry run release         # prompts for the level
pantry run release:dry     # preview, writes nothing
```

They all go through `scripts/release.ts`, which gates the release (clean `main`
in sync with origin, every manifest on the same version) and then runs bumpx
over an **explicit** manifest list — `package.json`, every
`packages/*/package.json`, `packages/zig/build.zig.zon`. The list is explicit
because `--recursive` discovery also reaches the vendored Zig dependencies under
`packages/zig/{vendor,zig-pkg,pantry}/` and would bump those too. bumpx
regenerates `CHANGELOG.md` via logsmith, commits, tags and pushes; the tag push
starts `.github/workflows/release.yml`.

bumpx only rewrites a manifest whose current version matches the one it is
bumping from, so a drifted manifest is skipped **silently**. `bun test scripts`
asserts they are all in lockstep and CI runs it on every PR.

See [docs/RELEASE_PROCESS.md](docs/RELEASE_PROCESS.md).

## Zig 0.16 Specifics

This project uses Zig 0.16.0-dev which has breaking changes from 0.15:

- `std.ArrayList` is unmanaged: init with `.empty`, pass allocator to every method (`append(allocator, ...)`, `deinit(allocator)`)
- `std.time.sleep` removed: use `time_compat.sleep()` (our wrapper using `std.c.nanosleep`)
- `std.fs.cwd()` removed: use `fs_compat` module for file operations
- `std.process.Child.run` removed: use `extern "c" fn system()` or C file I/O
- `std.c.stat/remove/system` removed: declare `extern "c"` functions directly
- Argon2 password hashing uses `p=1` (single-threaded) to avoid async I/O requirements in tests
- Custom compat layers: `src/core/io_compat.zig`, `src/core/fs_compat.zig`, `src/core/time_compat.zig`, `src/core/socket_compat.zig`

## Production Server

Reached over SSH. There is no SSM agent on this host, and no AWS instance behind
it — an earlier version of this file described an EC2 box in us-east-1 deployed
via `aws ssm send-command`, which no longer exists.

- **Host**: `178.105.248.188` — Hetzner, Ubuntu 24.04 LTS, x86_64
- **Hostname**: reports as `statushq-production-app`; the box is shared, so do
  not assume a unit belongs to mail just because it is running here
- **Domain**: `mail.stacksjs.com` (A record points at the IP above)
- **Access**: `ssh -i ~/.ssh/id_ed25519 root@178.105.248.188`
- **Binary**: `/opt/mail/mail-server`
- **Service**: `mail.service` — "Mail Server (Zig)", systemd, runs as the
  `mail-server` user with `CAP_NET_BIND_SERVICE`
- **Config**: `/etc/mail/mail.env`
- **Delivery**: `SMTP_DELIVERY_METHOD=direct` — this host sends its own mail. It
  is not relaying through SES.
- **TLS**: Let's Encrypt at `/etc/letsencrypt/live/mail.stacksjs.com/`
- **Ports**: 25 (SMTP), 465 (SMTPS), 587 (Submission), 143 (IMAP), 993 (IMAPS).
  ufw allows all five from anywhere, plus 22/80/443.

### State lives under /var/lib, not /opt

Everything in `/opt/mail` that holds data is a symlink into
`/var/lib/mail-storage/data/`. Follow the link before reasoning about a path,
and back up the real file rather than the symlink:

| via /opt/mail | real path |
|---|---|
| `smtp.db` | `/var/lib/mail-storage/data/smtp.db` |
| `mail/{username}/` | `/var/lib/mail-storage/data/mail/{username}/` |
| `dkim/` | `/var/lib/mail-storage/data/dkim/` |
| `forwards.json` | `/var/lib/mail-storage/data/forwards.json` |
| `backups/` | `/var/lib/mail-storage/data/backups/` |

Maildirs are named after the account's `username` column, which is **not always
the email address** — 12 of the current accounts are stored bare (`cloud`,
`zoltan`, `noreply`) and the rest use the full address. A bare-username account
will not authenticate with its email address.

`mail.log` sits beside them and is not rotated; it was 345MB as of 2026-10-05,
so `tail -c` a slice rather than reading it whole.

## Deployment over SSH

Cross-compile locally, ship the binary, restart the unit. Keep the old binary —
the convention on the box is `mail-server.bak-<epoch>`, and there are a dozen of
them from previous rollbacks.

```bash
# 1. Build for the server
cd packages/zig
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux

# 2. Ship it beside the running one
scp -i ~/.ssh/id_ed25519 zig-out/bin/mail root@178.105.248.188:/tmp/mail-server-new

# 3. Swap and restart
ssh -i ~/.ssh/id_ed25519 root@178.105.248.188 '
  cp /opt/mail/mail-server /opt/mail/mail-server.bak-$(date +%s)
  install -o mail-server -g mail-server -m 755 /tmp/mail-server-new /opt/mail/mail-server
  systemctl restart mail.service
  systemctl is-active mail.service
'

# 4. Confirm it came back on all five ports
ssh -i ~/.ssh/id_ed25519 root@178.105.248.188 \
  "ss -ltn | grep -cE ':(25|143|465|587|993)\\b'"   # expect 5

# Logs
ssh -i ~/.ssh/id_ed25519 root@178.105.248.188 \
  "journalctl -u mail.service --no-pager -n 100"
```

No `setcap` step. The binary carries no file capabilities (`getcap` on it is
empty) — port 25 works because the unit declares
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, which systemd grants at launch. Keep
the `install` ownership as `mail-server:mail-server 755`, matching what is there.

If the host key changes after a rebuild: `ssh-keygen -R mail.stacksjs.com`

## Cloud Infrastructure (packages/cloud)

> This describes `packages/cloud/cloud.config.ts` as written, not what is
> serving mail today. Production currently runs on the Hetzner host above,
> with `SMTP_DELIVERY_METHOD=direct` and DNS at Porkbun — no EC2, no SES
> relay, no Route 53. Treat this section as the AWS path the repo still
> supports, and verify against the live box before acting on it.

Defined in `cloud.config.ts` using ts-cloud (CloudFormation wrapper):

- **EC2**: t3 instance with security groups for mail ports
- **SES**: Domain verification, DKIM signing
- **Route 53**: MX, A, SPF, DMARC, DKIM DNS records
- **IAM**: Role with SES, S3, Route53, SSM permissions
- **S3**: `stacks-production-s3-email` for deployments and backups
- **User data script** handles: Zig install, build from git, Let's Encrypt, fail2ban, systemd service, log rotation, certbot renewal

Deploy infrastructure:
```bash
pantry run deploy          # Deploy CloudFormation stack
pantry run cloud:status    # Check stack status
pantry run cloud:diff      # Preview changes
```

## Discord Health Monitoring

The server includes a background health monitor (`src/observability/discord.zig`) that sends alerts to Discord via webhook. Checks include: active connections, database health, TLS cert expiry, disk space, and heartbeat.

Configure via environment variable:
```
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

## Key Architecture Decisions

- **Maildir format**: Messages stored as individual files with `:2,FLAGS` suffix (S=Seen, R=Answered, F=Flagged, D=Draft, T=Deleted)
- **IMAP flag persistence**: Flags are persisted by renaming maildir files. `BODY[]` (non-PEEK) auto-sets `\Seen` per RFC 3501
- **UID STORE**: Handles comma-separated UID sets (e.g., `83,85,88,90`) by converting UIDs to sequence numbers via `uidSetToSeqSet()`
- **Password hashing**: Argon2id with 64MB memory, 3 iterations, p=1 (format: `$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>`)
- **SQLite**: Primary database for user accounts, UID mappings, sessions
- **TLS**: Custom TLS 1.3 implementation via zig-tls dependency

## Testing

```bash
cd packages/zig && zig build test
```

Tests are split across multiple binaries (main, auth, imap, protocol, config, connection_wrapper, etc.). The logging tests produce stderr output which Zig's test runner reports as warnings — this is expected behavior, not a failure.

Test binaries link against `sqlite3` system library. The argon2 password tests use `p=1` to avoid needing async I/O vtable (which is uninitialized in the test runner).

## Common Tasks

- **Add a user**: `mail-server user add <email> <password>` (on server)
- **Check service**: `systemctl status mail` (on server via SSM)
- **View IMAP logs**: `journalctl -u mail | grep IMAP`
- **Backup**: `mail-server backup create` → S3 bucket `stacks-production-s3-backups`

---

## Linting

- Use **pickier** for linting — never use eslint directly
- Run `bunx --bun pickier .` to lint, `bunx --bun pickier . --fix` to auto-fix
- When fixing unused variable warnings, prefer `// eslint-disable-next-line` comments over prefixing with `_`

## Frontend

- Use **stx** for templating — never write vanilla JS (`var`, `document.*`, `window.*`) in stx templates
- Use **crosswind** as the default CSS framework which enables standard Tailwind-like utility classes
- stx `<script>` tags should only contain stx-compatible code (signals, composables, directives)

## Dependencies

- **buddy-bot** handles dependency updates — not renovatebot
- **better-dx** provides shared dev tooling as peer dependencies — do not install its peers (e.g., `typescript`, `pickier`, `bun-plugin-dtsx`) separately if `better-dx` is already in `package.json`
- If `better-dx` is in `package.json`, ensure `bunfig.toml` includes `linker = "hoisted"`
