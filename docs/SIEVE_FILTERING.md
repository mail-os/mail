# Sieve Filtering

Server-side mail filtering using the Sieve language (RFC 5228) with an extensible registry of capabilities.

## Purpose

Sieve is a language for filtering email messages at the point of final delivery. Unlike client-side rules, Sieve scripts execute on the server so they apply regardless of which client or device retrieves the mail. The mail server implements a Sieve extension registry that manages available capabilities, validates scripts, and handles dependency resolution.

## Relevant RFCs

- **RFC 5228** -- Sieve: An Email Filtering Language (core)
- **RFC 5429** -- Reject and Extended Reject Extensions
- **RFC 5230** -- Vacation Extension
- **RFC 5229** -- Variables Extension
- **RFC 5232** -- Imap4flags Extension
- **RFC 5173** -- Body Extension
- **RFC 3894** -- Copying Without Side Effects

## Configuration

### Environment Variables

```bash
SMTP_ENABLE_SIEVE=true
SMTP_ENABLE_MANAGESIEVE=true
SMTP_MANAGESIEVE_PORT=4190
```

### TOML Configuration

```toml
[sieve]
enabled = true

[managesieve]
enabled = true
port = 4190
```

## Supported Commands

### Control Commands

| Command                | Description                                         |
|------------------------|-----------------------------------------------------|
| `require ["ext", ...]` | Declare required extensions before use              |
| `if / elsif / else`    | Conditional branching based on test results          |
| `stop`                 | Halt script execution; apply implicit keep           |

### Action Commands

| Command              | Description                                           |
|----------------------|-------------------------------------------------------|
| `keep`               | Deliver message to default mailbox (explicit keep)    |
| `fileinto "folder"`  | Deliver message into a named mailbox                  |
| `redirect "addr"`    | Forward message to another address                    |
| `discard`            | Silently discard the message                          |
| `reject "reason"`    | Refuse delivery with an MDN to the sender (RFC 5429)  |

## Supported Tests

| Test       | Description                                              |
|------------|----------------------------------------------------------|
| `header`   | Match against message header field values                |
| `address`  | Match against structured address headers (From, To, etc) |
| `envelope` | Match against SMTP envelope sender/recipient (RFC 5228)  |
| `size`     | Compare message size (`:over` / `:under`)                |
| `exists`   | Test whether a header field exists                       |
| `allof`    | Logical AND -- all sub-tests must match                  |
| `anyof`    | Logical OR -- at least one sub-test must match           |
| `not`      | Logical negation of a test                               |
| `true`     | Always matches                                           |
| `false`    | Never matches                                            |

## Match Types

- `:is` -- Exact match
- `:contains` -- Substring match
- `:matches` -- Glob-style wildcard matching (`*` and `?`)

Comparators: `"i;ascii-casemap"` (case-insensitive, default), `"i;octet"` (exact bytes).

## Built-in Extensions

| Extension     | RFC   | Default  | Description                                    |
|---------------|-------|----------|------------------------------------------------|
| `fileinto`    | 5228  | Enabled  | Deliver to named mailbox                       |
| `reject`      | 5429  | Enabled  | Refuse delivery with MDN                       |
| `envelope`    | 5228  | Enabled  | Access envelope sender/recipient               |
| `body`        | 5173  | Enabled  | Test against message body content              |
| `vacation`    | 5230  | Enabled  | Automatic out-of-office replies                |
| `imap4flags`  | 5232  | Enabled  | Manipulate IMAP flags and keywords             |
| `variables`   | 5229  | Enabled  | Variable support and expansion                 |
| `copy`        | 3894  | Enabled  | Copy without cancelling implicit keep          |
| `relational`  | 5231  | Enabled  | Relational/numeric comparators                 |
| `notify`      | 5435  | Disabled | External notification channels                 |
| `editheader`  | 5293  | Disabled | Add/remove message header fields               |
| `regex`       | draft | Disabled | Regular expression matching                    |

## Script Example

```sieve
require ["fileinto", "reject", "vacation"];

if address :is "from" "spammer@bad-domain.com" {
    reject "Unsolicited mail is not accepted.";
}

if header :contains "List-Id" "dev-discuss" {
    fileinto "Lists.dev-discuss";
    stop;
}

vacation :days 7 :subject "Out of Office"
    "I am currently out of the office.";

if size :over 10M {
    fileinto "LargeMessages";
    stop;
}
```

## Script Management (ManageSieve)

Scripts are uploaded and managed via the ManageSieve protocol (RFC 5804) on port 4190. The server validates every script's `require` list against the extension registry before accepting it. Validation checks for:

- **Missing extensions** -- capability not registered on the server
- **Disabled extensions** -- capability registered but administratively disabled
- **Missing dependencies** -- e.g., `copy` requires `fileinto`

## See Also

- [IMAP/POP3 Guide](IMAP_POP3.md)
- [Configuration Guide](CONFIGURATION.md)
- Source: `src/features/sieve_extensions.zig`, `src/protocol/managesieve.zig`
