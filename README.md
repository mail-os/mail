# Mail

[![CI](https://github.com/stacksjs/mail/workflows/CI/badge.svg)](https://github.com/stacksjs/mail/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-0.16.0--dev-orange.svg)](https://ziglang.org/)

A performant and secure mail server implementation written in Zig, designed for self-hosting email infrastructure. Supports SMTP, IMAP, POP3, CalDAV/CardDAV, ActiveSync, and more.

## Features

### Core Protocols

- **SMTP** (RFC 5321): Full ESMTP with SIZE, 8BITMIME, PIPELINING, AUTH (PLAIN, LOGIN), STARTTLS
- **IMAP** (IMAP4rev1): 24 commands, folder management, search, flags
- **POP3**: Standard mailbox retrieval
- **CalDAV/CardDAV**: Calendar and contact sync
- **ActiveSync**: Mobile device sync
- **ManageSieve**: Server-side mail filtering
- **Milter**: Mail filter protocol support

### Enterprise Features

- **Multi-Tenancy**: Complete tenant isolation with four tiers, resource limits, and REST API
- **Cluster Mode**: Leader election, distributed state, automatic failover, health monitoring
- **Machine Learning Spam Detection**: Built-in ML-based spam filtering
- **DKIM/SPF/DMARC/ARC/BIMI**: Full email authentication suite
- **DANE & MTA-STS**: Transport security enforcement
- **ACME**: Automatic certificate management
- **Webhook Notifications**: HTTP POST on incoming mail events
- **WebSocket**: Real-time notifications

### Security & Operations

- Per-IP and per-user rate limiting
- Connection limits and max recipients enforcement
- RFC-compliant email validation and input sanitization
- TOML configuration with hot reload (SIGHUP)
- Multi-level structured logging (file + console, JSON or text)
- Distributed tracing (Jaeger, DataDog, Zipkin, OTLP)
- Alerting (Slack, PagerDuty, OpsGenie, webhooks)
- Secret management (Vault, K8s Secrets, AWS, Azure)
- io_uring integration for Linux
- GDPR data export and deletion

## Requirements

- Zig 0.16.0-dev or later
- POSIX-compliant system (Linux, macOS, BSD)

## Project Structure

This is a monorepo managed by [pantry](https://github.com/stacksjs/pantry):

```
.
├── pantry.jsonc              # Root workspace config
├── config.toml               # Server configuration
├── packages/
│   ├── zig/                  # Core mail server (Zig)
│   │   ├── build.zig
│   │   ├── build.zig.zon
│   │   └── src/
│   │       ├── mail_cli.zig  # CLI entry point
│   │       ├── cli/          # CLI subcommands
│   │       ├── core/         # SMTP server, config, logging
│   │       ├── protocol/     # IMAP, POP3, CalDAV, DSN, etc.
│   │       ├── auth/         # Authentication
│   │       ├── security/     # Secrets, ACME
│   │       ├── antispam/     # DKIM, SPF, DANE, greylisting
│   │       ├── delivery/     # Mail delivery, TLS reporting
│   │       ├── features/     # GDPR, sieve, multi-tenancy
│   │       ├── storage/      # Database, maildir
│   │       ├── observability/ # Metrics, tracing, alerting
│   │       ├── infrastructure/ # Cluster mode
│   │       ├── api/          # REST API, webmail, swagger
│   │       └── tools/        # SDK generator, migrations
│   ├── ts/                   # TypeScript SDK
│   └── cloud/                # AWS deployment (ts-cloud)
├── docs/                     # Documentation
├── examples/                 # Usage examples
├── scripts/                  # Build & release scripts
└── tests/                    # Integration tests
```

## Getting Started

### Install Dependencies

```bash
pantry install
```

### Build

```bash
# Release build
pantry run build

# Debug build
pantry run build:debug
```

### Run

```bash
# Development mode
pantry run dev

# Or run the compiled binary directly
./packages/zig/zig-out/bin/mail serve
```

## CLI Reference

The `mail` CLI provides the following commands:

### `mail serve`

Start the mail server.

```bash
mail serve [OPTIONS]

Options:
  -c, --config <FILE>         Path to configuration file
      --host <HOST>           Host to bind to (default: 0.0.0.0)
  -p, --port <PORT>           Port to listen on (default: 2525)
      --log-level <LEVEL>     Log level: debug|info|warn|error|critical
      --log-file <FILE>       Path to log file (default: mail.log)
      --max-connections <N>   Maximum concurrent connections
      --validate-only         Validate configuration and exit
      --enable-tls            Enable TLS/STARTTLS support
      --disable-tls           Disable TLS/STARTTLS support
      --enable-auth           Enable SMTP authentication
      --disable-auth          Disable SMTP authentication
```

```bash
# Examples
mail serve --port 587 --log-level debug
mail serve --host 127.0.0.1 --port 2525 --max-connections 200
mail serve --config /etc/mail/config.toml
mail serve --validate-only
```

### `mail user`

Remote user management via AWS SSM.

```bash
mail user create <email> [--password <pass>] [--instance-id <id>] [--env <env>]
mail user delete <username> [--instance-id <id>] [--env <env>]
mail user disable <username> [--instance-id <id>] [--env <env>]
mail user enable <username> [--instance-id <id>] [--env <env>]
mail user info <username> [--instance-id <id>] [--env <env>]
mail user verify <username> <password> [--instance-id <id>] [--env <env>]
mail user change-password <username> <password> [--instance-id <id>] [--env <env>]
```

### `mail user:local`

Local user management (direct database access).

```bash
mail user:local create <username> <password> <email>
mail user:local delete <username>
mail user:local disable <username>
mail user:local enable <username>
mail user:local info <username>
mail user:local verify <username> <password>
mail user:local change-password <username> <password>
```

### `mail migrate`

Database migration management.

```bash
mail migrate up          # Apply all pending migrations
mail migrate down        # Rollback the last migration
mail migrate status      # Show current migration status
mail migrate history     # Show migration history
mail migrate validate    # Validate migration order
mail migrate to <ver>    # Migrate to a specific version
```

### `mail search`

Search email messages.

```bash
mail search [<query>] [OPTIONS]

Options:
  --email <addr>        Filter by email address
  --folder <name>       Filter by folder
  --limit <N>           Limit results (default: 100)
  --offset <N>          Skip N results
  --from-date <ts>      Filter from date (Unix timestamp)
  --to-date <ts>        Filter to date (Unix timestamp)
  --attachments         Only show messages with attachments
  --sort <order>        Sort by: received-asc, received-desc, relevance, sender-asc

# Subcommands
mail search sender <address> [--limit <N>]
mail search subject <text> [--limit <N>]
mail search date-range <from> <to> [--email <addr>]
mail search stats
mail search rebuild-index
```

### `mail gdpr`

GDPR data protection commands.

```bash
mail gdpr export <username> [<output_file>]   # Export user data to JSON
mail gdpr delete <username>                    # Delete all user data
mail gdpr log <username> <action> <ip>         # Log data access
```

### `mail benchmark`

Performance benchmarking.

```bash
mail benchmark run [--json]    # Run all benchmarks
mail benchmark list            # List available benchmarks
```

### `mail backup`

Production backup and status commands via AWS SSM.

```bash
# Create a backup (stops service, archives data, uploads to S3, restarts)
mail backup create [--instance-id <id>] [--env <environment>] [--bucket <name>]

# Restore from a backup
mail backup restore <backup-file> [--instance-id <id>] [--env <environment>] [--bucket <name>]

# List available backups in S3
mail backup list [--instance-id <id>] [--env <environment>] [--bucket <name>]

# Show server status (service, disk, database, mailboxes, TLS, uptime)
mail backup status [--instance-id <id>] [--env <environment>]
```

Options:
- `--instance-id <id>` — EC2 instance ID (auto-detected from CloudFormation if omitted)
- `--env <environment>` — Environment: `production`, `staging`, `dev` (default: `production`)
- `--bucket <name>` — S3 bucket for backups (auto-detected from stack or by prefix search)

## Configuration

Configuration uses TOML format. See `config.example.toml` for all options.

```bash
# Copy and customize
cp config.example.toml config.toml
```

Configuration priority (highest to lowest):
1. Command-line arguments
2. Environment variables (`SMTP_*`)
3. Configuration file (`config.toml`)
4. Profile defaults (`SMTP_PROFILE` env var)

Key environment variables:
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_HOSTNAME`
- `SMTP_MAX_CONNECTIONS`, `SMTP_MAX_RECIPIENTS`, `SMTP_MAX_MESSAGE_SIZE`
- `SMTP_ENABLE_TLS`, `SMTP_ENABLE_AUTH`
- `SMTP_TLS_CERT`, `SMTP_TLS_KEY`
- `SMTP_WEBHOOK_URL`

## Deployment

### AWS Deployment

The `packages/cloud` package provides AWS infrastructure via [ts-cloud](https://github.com/stacksjs/ts-cloud):

```bash
# Deploy to production
pantry run deploy:prod

# Check status
pantry run cloud:status

# View diff before deploying
pantry run cloud:diff
```

See [packages/cloud/README.md](packages/cloud/README.md) for detailed deployment docs.

### Docker

```bash
pantry run docker:build
pantry run docker:run
```

### Running on Port 25

```bash
# Grant capability (Linux)
sudo setcap 'cap_net_bind_service=+ep' packages/zig/zig-out/bin/mail
./packages/zig/zig-out/bin/mail serve

# Or use iptables redirect
sudo iptables -t nat -A PREROUTING -p tcp --dport 25 -j REDIRECT --to-port 2525
```

## Testing

```bash
# Unit tests
pantry run test

# Manual SMTP test
telnet localhost 2525
EHLO client.example.com
MAIL FROM:<sender@example.com>
RCPT TO:<recipient@example.com>
DATA
Subject: Test
This is a test.
.
QUIT
```

## Development

```bash
# Format code
pantry run fmt

# Cross-compile for all platforms
pantry run cross

# Release
pantry run release:patch   # or release:minor, release:major
```

## Contributing

1. Code follows Zig formatting (`zig fmt`)
2. Tests pass (`zig build test`)
3. Security considerations are addressed
4. Documentation is updated

## License

MIT License - See LICENSE file for details
