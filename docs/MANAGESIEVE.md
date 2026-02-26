# ManageSieve - Remote Sieve Script Management

**RFC:** 5804
**Source:** `src/protocol/managesieve.zig`

## Overview

ManageSieve (RFC 5804) is a protocol for remotely managing Sieve email filtering
scripts on a mail server. It runs on port 4190 and allows users to upload, activate,
deactivate, list, and delete Sieve scripts without direct filesystem access. This
enables mail clients and web interfaces to manage server-side filtering rules.

## Protocol Basics

- **Port:** 4190 (IANA-assigned)
- **Transport:** TCP with optional STARTTLS upgrade
- **Authentication:** SASL PLAIN (over TLS)
- **Line format:** Commands and responses are line-oriented, with string literals using `{size+}\r\n` syntax

### Connection Flow

```
S: "IMPLEMENTATION" "Zig Mail ManageSieve v1.0"
S: "SASL" "PLAIN"
S: "SIEVE" "fileinto reject envelope vacation ..."
S: "STARTTLS"
S: OK
C: STARTTLS
S: OK
C: AUTHENTICATE "PLAIN" "<base64 credentials>"
S: OK
C: LISTSCRIPTS
S: "default" ACTIVE
S: "vacation-reply"
S: OK
C: LOGOUT
S: OK
```

## Commands

| Command | Description |
|---------|-------------|
| `AUTHENTICATE` | Authenticate via SASL mechanism |
| `CAPABILITY` | Request server capabilities |
| `STARTTLS` | Upgrade connection to TLS |
| `HAVESPACE` | Check if server has space for a script of given size |
| `PUTSCRIPT` | Upload a new script or replace an existing one |
| `LISTSCRIPTS` | List all scripts and indicate which is active |
| `SETACTIVE` | Set a script as the active filter (or deactivate with empty name) |
| `GETSCRIPT` | Retrieve the contents of a named script |
| `DELETESCRIPT` | Delete a named script (cannot delete the active script) |
| `RENAMESCRIPT` | Rename an existing script |
| `CHECKSCRIPT` | Validate a script without storing it |
| `NOOP` | Keep-alive / no operation |
| `LOGOUT` | End the session |

## Server Capabilities

The server advertises these capabilities during the greeting and after `CAPABILITY`:

| Capability | Value |
|-----------|-------|
| `IMPLEMENTATION` | Server name and version string |
| `SASL` | Supported SASL mechanisms (e.g., `PLAIN`) |
| `SIEVE` | Space-separated list of supported Sieve extensions |
| `STARTTLS` | Present if STARTTLS is available |

## Response Codes

The server may include response codes in `OK`, `NO`, or `BYE` responses:

| Code | Meaning |
|------|---------|
| `AUTH-TOO-WEAK` | Authentication mechanism is too weak |
| `ENCRYPT-NEEDED` | TLS required before authentication |
| `QUOTA` | User quota exceeded |
| `QUOTA/MAXSCRIPTS` | Maximum number of scripts reached |
| `QUOTA/MAXSIZE` | Script exceeds maximum size |
| `NONEXISTENT` | Referenced script does not exist |
| `ALREADYEXISTS` | Script name already in use (rename) |
| `ACTIVE` | Cannot delete the active script |
| `TRYLATER` | Temporary server error; retry later |

## Configuration

### Environment Variables

```bash
SMTP_ENABLE_MANAGESIEVE=true
SMTP_MANAGESIEVE_PORT=4190
```

### Configuration File

```ini
[managesieve]
enabled = true
```

### Key Configuration Fields

See `ManageSieveConfig` in the source for the full struct. Key fields:

| Field | Default | Description |
|-------|---------|-------------|
| `port` | `4190` | ManageSieve listening port |
| `max_connections` | `100` | Maximum concurrent connections |
| `enable_tls` | `true` | Enable STARTTLS support |
| `max_script_size` | `1048576` | Maximum script size in bytes (1 MB) |
| `max_scripts_per_user` | `100` | Maximum scripts per user |
| `script_dir` | `/var/sieve` | Filesystem directory for script storage |

## References

- [RFC 5804 - A Protocol for Remotely Managing Sieve Scripts](https://datatracker.ietf.org/doc/html/rfc5804)
- [RFC 5228 - Sieve: An Email Filtering Language](https://datatracker.ietf.org/doc/html/rfc5228)
- [RFC 4422 - Simple Authentication and Security Layer (SASL)](https://datatracker.ietf.org/doc/html/rfc4422)
