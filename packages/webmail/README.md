# webmail

Browser webmail client for the mail server — the stx frontend half of the plan
in [`../../WEBMAIL.md`](../../WEBMAIL.md).

The browser never speaks IMAP/SMTP. This app renders the UI and calls a small
JSON API (`/webmail/*`) served by the Zig mail server, which is the only thing
that touches the mailbox (Maildir + SQLite) and the delivery queue. The Stacks
framework is **not** involved.

## Layout

```text
pages/        file-based routes (index.stx -> /, login.stx -> /login)
layouts/      shared page shells
components/   auto-imported components (AppShell, ...)
functions/    composables / API client (useApi.ts)
public/       static assets (styles.css)
stx.config.ts stx configuration
server.ts     dev server + /webmail/* proxy to the Zig API
build.ts      prod build (Phase 9 — not implemented yet)
```

## Develop

```bash
bun install            # from repo root or here
bun run dev            # http://localhost:5173
```

`server.ts` proxies `/webmail/api/*` and `/webmail/auth/*` to `API_TARGET`
(default `http://127.0.0.1:8080`). The Zig HTTP listener doesn't exist yet
(WEBMAIL.md Phase 2), so those calls return a labelled `502` until it's wired up
— that's expected at this stage.

## Status

**Phase 0** (scaffold) per WEBMAIL.md. crosswind, real auth, the 3-pane inbox,
and the production build are deliberately stubbed and called out inline.
