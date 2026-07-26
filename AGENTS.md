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

- **Instance**: `i-0e365c6bd31da4678` (EC2, Amazon Linux 2023, us-east-1)
- **Domain**: `mail.stacksjs.com`
- **Binary**: `/opt/mail/mail-server` (renamed from `mail` to avoid conflict with `mail/` mailbox dir)
- **Mailboxes**: `/opt/mail/mail/{username}/new/` (Maildir format)
- **Database**: `/opt/mail/smtp.db` (SQLite)
- **Config**: `/etc/mail/mail.env`
- **TLS**: Let's Encrypt at `/etc/letsencrypt/live/mail.stacksjs.com/`
- **Service**: `mail.service` (systemd, runs as `mail-server` user with `CAP_NET_BIND_SERVICE`)
- **Delivery**: Amazon SES (`SMTP_DELIVERY_METHOD=ses`)
- **Ports**: 25 (SMTP), 465 (SMTPS), 587 (Submission), 143 (IMAP), 993 (IMAPS)

## Deployment via AWS SSM

Deploy new builds without SSH. The server has SSM agent running and an IAM role with SSM permissions.

```bash
# 1. Cross-compile for Linux
cd packages/zig
zig build -Dtarget=x86_64-linux

# 2. Upload binary to S3
aws s3 cp zig-out/bin/mail s3://stacks-production-s3-email/deploy/mail-server-new

# 3. Deploy via SSM (stop service, swap binary, restart)
aws ssm send-command \
  --instance-ids i-0e365c6bd31da4678 \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=[
    "aws s3 cp s3://stacks-production-s3-email/deploy/mail-server-new /tmp/mail-server-new",
    "chmod +x /tmp/mail-server-new",
    "systemctl stop mail",
    "cp /opt/mail/mail-server /opt/mail/mail-server.bak",
    "mv /tmp/mail-server-new /opt/mail/mail-server",
    "chown mail-server:mail-server /opt/mail/mail-server",
    "systemctl start mail",
    "sleep 2",
    "systemctl is-active mail"
  ]'

# 4. Check result
aws ssm get-command-invocation \
  --command-id <COMMAND_ID> \
  --instance-id i-0e365c6bd31da4678

# View logs
aws ssm send-command \
  --instance-ids i-0e365c6bd31da4678 \
  --document-name "AWS-RunShellScript" \
  --parameters 'commands=["journalctl -u mail --no-pager -n 100"]'
```

The old host key may need updating after instance rebuilds:
```bash
ssh-keygen -R mail.stacksjs.com
```

## Cloud Infrastructure (packages/cloud)

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
- **List domains**: `mail-server domain list`
- **Rename a domain**: `mail-server domain migrate <old> <new>` (see below)

## Domain Migration

A project renames itself and its mail domain has to follow. Doing that by hand
means editing five things that must agree, and the mailbox goes dark if any one
is missed:

1. `users` — `username` and `email` are both the full address, both UNIQUE
2. `imap_mailboxes` / `imap_uids` — keyed by `username`; losing these makes
   every client re-download the mailbox and lose read/flag state
3. `webmail_sessions` — carry a baked-in identity
4. Maildirs at `/opt/mail/mail/<address>`
5. `/opt/mail/forwards.json` — keys and destinations

`domain migrate` does all five in one pass. It prints a plan and changes
nothing unless `--yes` is given:

```bash
mail-server domain list                                   # what is in use
mail-server domain migrate ghostanalytics.org analyticshq.org
mail-server domain migrate ghostanalytics.org analyticshq.org --yes
```

It refuses up front when a target address is already taken — `username` and
`email` are UNIQUE, so the UPDATE would abort partway and strand the domain
across two names. Merge or delete the conflicting mailbox first.

The database moves in one transaction; maildir renames follow. A maildir that
fails to rename is reported by name, because the alternative (rolling back with
directories already moved) is worse.

**Not automated**, and printed as a reminder at the end of every run:

- add the new domain to `SMTP_LOCAL_DOMAINS` in `/etc/mail/mail.env`, and keep
  the old one until mail has drained
- generate a DKIM key for the new domain and publish its TXT record — mail from
  a domain with no key arrives unsigned and gets filtered
- MX, SPF and DMARC for the new domain

Paths come from `MAIL_ROOT`, `MAIL_FORWARDS_PATH` and `MAIL_DKIM_DIR`, all
relative to the working directory by default (`/opt/mail` in production).

Source: `src/domain_migrate.zig` (planning), `src/cli/domain.zig` (CLI),
`Database.renameDomain` (the SQL, in one transaction).

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
