# Milter - Mail Filter Protocol

**Source:** `src/protocol/milter.zig`

## Overview

The Milter (Mail Filter) protocol allows an MTA to delegate message inspection and
modification to external filter programs. Originally developed for Sendmail, the
milter protocol is now widely supported and used to integrate filters such as
SpamAssassin (spamass-milter), ClamAV (clamav-milter), OpenDKIM, and OpenDMARC.

## Binary Protocol Format

Milter uses a simple binary packet format over TCP or Unix domain sockets:

```
+----------+----------+--------------------+
|  uint32  |  uint8   |   variable data    |
|   len    |   cmd    |   (len-1 bytes)    |
+----------+----------+--------------------+
```

- **len**: 4-byte big-endian (network byte order) length of `cmd + data`
- **cmd**: Single-byte command or response identifier
- **data**: Variable-length payload (may be empty)

## Connection Types

| Type | Example | Description |
|------|---------|-------------|
| Unix socket | `/var/run/milter.sock` | Local filters on the same host |
| TCP | `127.0.0.1:8893` | Remote filters or containers |

Configuration requires exactly one connection method (not both).

## Protocol Flow

```
OPTNEG -> CONNECT -> HELO -> MAIL -> RCPT -> HEADER(s) -> EOH -> BODY(s) -> BODYEOB -> QUIT
```

The milter responds at each stage (typically `SMFIR_CONTINUE`). It can
short-circuit at any point with a final action (accept, reject, discard).

## Action Flags (SMFIF_*)

Negotiated during `SMFIC_OPTNEG`, these flags declare what the milter is permitted
to do:

| Flag | Description |
|------|-------------|
| `SMFIF_ADDHDRS` | Add headers |
| `SMFIF_CHGHDRS` | Change or delete headers |
| `SMFIF_CHGBODY` | Replace message body |
| `SMFIF_ADDRCPT` | Add recipients |
| `SMFIF_DELRCPT` | Remove recipients |
| `SMFIF_QUARANTINE` | Quarantine the message |
| `SMFIF_CHGFROM` | Change envelope sender (v6) |
| `SMFIF_ADDRCPT_PAR` | Add recipients with ESMTP params (v6) |
| `SMFIF_SETSYMLIST` | Request specific macro symbols (v6) |

## Protocol Step Flags (SMFIP_*)

These flags tell the MTA which callbacks the milter does **not** need, reducing
overhead. Common flags: `SMFIP_NOCONNECT`, `SMFIP_NOHELO`, `SMFIP_NOMAIL`,
`SMFIP_NORCPT`, `SMFIP_NOBODY`, `SMFIP_NOHDRS`, `SMFIP_NOEOH`.

## Response Actions

| Response | Meaning |
|----------|---------|
| `SMFIR_CONTINUE` | Continue to next callback |
| `SMFIR_ACCEPT` | Accept the message |
| `SMFIR_REJECT` | Reject with 5xx |
| `SMFIR_TEMPFAIL` | Temporary failure (4xx) |
| `SMFIR_DISCARD` | Silently discard |
| `SMFIR_QUARANTINE` | Quarantine the message |

## Configuration

### Environment Variable

```bash
SMTP_ENABLE_MILTER=true
```

### Configuration File

```ini
[milter]
enabled = true
```

### Programmatic Configuration

```zig
// Unix socket                              // TCP
const config = MilterConfig{                const config = MilterConfig{
    .socket_path = "/var/run/milter.sock",      .host = "127.0.0.1",
    .timeout_ms = 30_000,                       .port = 8893,
    .name = "spamassassin",                     .name = "clamav",
};                                          };
```

### Milter Pipeline

Multiple milters can be chained using `MilterManager`. Messages flow through each
filter in order; if any rejects, the pipeline short-circuits.

```zig
var manager = MilterManager.init(allocator);
try manager.addMilter(.{ .socket_path = "/var/run/opendkim.sock", .name = "opendkim" });
try manager.addMilter(.{ .host = "127.0.0.1", .port = 8893, .name = "spamassassin" });
```

## References

- [Sendmail Milter API Documentation](https://www.sendmail.org/doc/sendmail-current/libmilter/docs/)
- [Postfix Milter Support](http://www.postfix.org/MILTER_README.html)
