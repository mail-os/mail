# Trap mode (the mailpit replacement)

A development mail catcher and a production mail server are conventionally two
different programs, and that difference is where mail breaks. A message that
renders in mailpit has been through a parser nothing in production will ever
run; a `From` header mailpit accepts is one no real MTA would. The bugs that
costs are the ones nobody can reproduce locally.

Trap mode removes the difference. It is this server, with delivery switched off:

```toml
[server]
host = "127.0.0.1"
port = 1025
hostname = "localhost"
catch_all = true

[tls]
enabled = false

[auth]
enabled = false
```

```sh
SMTP_ENABLE_WEBMAIL=true SMTP_WEBMAIL_PORT=8025 SMTP_WEBMAIL_SECURE_COOKIES=false \
  mail serve --config catcher.toml
```

SMTP on 1025, webmail on 8025 — mailpit's ports, so anything already pointed at
a mailpit is already pointed at this.

## What it does

- **Accepts mail for every domain.** `catch_all` makes `isLocalDomain` answer
  true for anything, so the RCPT gate stops refusing unauthenticated mail to
  addresses this server does not host. Without it a trap catches nothing: an
  application sends to whatever addresses its fixtures contain and gets
  `550 relay access denied` for all of them.
- **Delivers everything into one mailbox** (`catch_all_mailbox`, default `dev`).
  One inbox is what makes a trap readable — a developer wants the list of what
  the app just sent, not a mailbox per fixture address. It also avoids the
  collision where `someone@a.test` and `someone@b.test` both file under
  `someone`.
- **Creates that mailbox on first start**, so webmail has an account to sign in
  with: username `dev`, password `dev`, printed to the log. Fixed rather than
  generated because a trap is loopback-only by construction, so the secret
  protects nothing and a generated one would have to be fished out of a log on
  every restart.
- **Serves webmail without SMTP AUTH.** The database and auth backend are
  initialised whenever webmail is enabled, not only when `[auth]` is on.

## What it refuses

**A trap must not be reachable from anywhere but the machine running it.** A
server that accepts mail for every domain and files it locally is an open
relay's more embarrassing cousin: it does not forward the spam, it keeps it.

So `serve` refuses to start when `catch_all` is on and `host` is not a loopback
address:

```
Configuration Error: catch_all is on but the server binds 0.0.0.0.
A catch-all accepts mail for every domain and must stay on 127.0.0.1 or ::1.
```

## IMAP and CalDAV

Both default to on when `[auth]` is enabled, and both now bind the interface
`[server] host` names rather than `0.0.0.0` — a server told to bind loopback
meant it, and an IMAP listener that ignored that was publishing mailboxes to the
local network from a process the operator had confined.

`IMAP_ENABLED` and `CALDAV_ENABLED` are parsed as booleans. They used to be
tested with `!= null`, so **`IMAP_ENABLED=0` switched IMAP on** and there was no
way to switch it off. `0`, `false`, `no` and `off` now mean off.
