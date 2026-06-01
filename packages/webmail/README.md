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
public/       static assets (styles.css)
stx.config.ts stx configuration
server.ts     dev server + /webmail/* proxy to the Zig API
build.ts      prod build (Phase 9 — not implemented yet)
```

### Why standalone pages (no layouts/components)

Each page is a **full standalone HTML document** with a self-contained
`<script>` that does explicit DOM rendering — the same approach as the proven
`packages/devtools/pages/app.stx`. We deliberately do **not** use stx
`@extends` layouts or Alpine-style reactive directives (`x-data`/`@click`/
`x-model`) here: under a layout, stx strips those directives from the DOM
without attaching the reactive runtime, so they silently don't work. Vanilla
`addEventListener` + `innerHTML` is reliable across the stx SPA router. See the
inline comments and the project memory note `stx-client-side-gotchas`.

## Develop

```bash
bun install            # from repo root or here
bun run dev            # http://localhost:5173
```

`server.ts` proxies `/webmail/api/*` and `/webmail/auth/*` to `API_TARGET`
(default `http://127.0.0.1:8080`; the Zig server runs webmail on `:8099` when
`SMTP_ENABLE_WEBMAIL=true`, so use `API_TARGET=http://127.0.0.1:8099`). If the
backend is down, proxied calls return a labelled `502`.

## Status

**Phase 3 done** (WEBMAIL.md): login + 3-pane inbox (folders, message list,
reading pane with sandboxed HTML), wired to the live Zig backend and verified
end-to-end in a browser. Next: flags/actions (Phase 5), compose (Phase 6),
crosswind, and the production build (Phase 9).
