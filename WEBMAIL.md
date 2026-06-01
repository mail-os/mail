# Webmail UI — Implementation Plan

> **Status:** Phases 0–2 done — frontend scaffold + backend HTTP API serving real mail (login, folders, messages) end-to-end. Next: Phase 3 (frontend app shell & auth UI).
> **Owner:** TBD
> **Last updated:** 2026-06-01
> **Estimated effort:** ~8–12 weeks (multi-phase, see [Phases](#phases))

This document is the single source of truth for building a browser-based webmail
client for this mail server. It captures (1) the **real current state** of the
codebase, (2) the **target architecture**, and (3) a **phased plan** broken into
shippable increments.

Read [Current State](#current-state) first — it corrects the common assumption
that "there is no UI yet." There is a lot of *scaffolding and design work*, but
**none of it is live and none of it serves real mail.**

---

## Goals

### Primary goal
A user (e.g. someone with a mailbox like `you@mail.stacksjs.com`) can open a
browser, log in with their mail credentials, and **read, search, organize, and
send email** from their real mailbox — the same mailbox Apple Mail talks to over
IMAP/SMTP.

### Non-goals (for v1)
- Admin/operator dashboard (separate effort; `api.zig` + `admin.html` already
  partially cover this).
- Calendar/Contacts UI (CalDAV/CardDAV exist at the protocol level; defer).
- Mobile native apps.
- Multi-account / multi-tenant switching within one session.

### Success criteria for v1 ("usable daily")
- [ ] Log in / log out with mailbox credentials over HTTPS with a secure session.
- [ ] See folders with accurate unread counts (Inbox, Sent, Drafts, Trash, …).
- [ ] List messages in a folder with pagination and basic search.
- [ ] Open a message: rendered HTML (sanitized), plain-text fallback, headers,
      attachments (download).
- [ ] Mark read/unread, flag/star, delete, move — **persisted** so Apple Mail
      sees the same state (Maildir flags / IMAP consistency).
- [ ] Compose, reply, reply-all, forward → actually delivered via the existing
      delivery queue / SES path.
- [ ] Works on desktop + responsive on mobile.

---

## Current State

> Evidence-based inventory as of 2026-05-29. Legend:
> **🟢 Live** = wired in and working · **🟡 Code-complete but dead** = compiles
> but never invoked · **🔵 Mock** = returns fake/in-memory data · **⚪ Mockup** =
> static design reference · **🔴 Missing** = does not exist.

### What exists

| Component | Path | Status | Notes |
|---|---|---|---|
| Webmail handler (Zig) | `packages/zig/src/api/webmail.zig` (4203 ln) | 🟡 + 🔵 | Full `WebmailHandler` with routes for folders/messages/compose/search/attachments/threads/templates/signatures/receipts/scheduled/groups. **Never imported anywhere.** All handlers return **mock/in-memory data** — does *not* read Maildir or SQLite. |
| Embedded SPA | `webmail.zig` `serveMainPage()` (HTML ~ln 1309–4070) | 🟡 | A **complete** ~2,760-line vanilla-JS/CSS 3-pane SPA embedded as a Zig string literal (compose modal, rich-text editor, attachments, threading, contacts, dark mode, mobile responsive). Fetches `/webmail/api/*`. Strong visual base — but dead (never served) and its API returns mock data. |
| Webmail API handlers | `webmail.zig` `handleApiGet/Post/Delete` | 🔵/🟡 | **Split:** `folders`/`messages`/`user`/`compose`/`search` return **hardcoded/empty** JSON. `threads`/`templates`/`signatures`/`scheduled`/`groups`/inline-images are wired to real **in-memory** feature managers (no SQLite/Maildir, lost on restart). No `*Database` or Maildir field on `WebmailHandler`. |
| Admin REST API | `packages/zig/src/api/api.zig` (~1600 ln) | 🟡 | Complete `APIServer`: `/api/users` (CRUD), `/api/stats`, `/api/queue`, `/api/filters`, `/api/search(+rebuild)`, `/api/config`, `/api/logs`, `/api/audit`, `/api/csrf-token`, GraphQL, autoconfig, password-reset, CSRF on mutations. **Never instantiated in `main.zig` — fully dead code.** |
| Admin dashboard page | `packages/zig/src/api/admin.html` (708 ln) | 🟡 | Complete dashboard, but only served by `api.zig`, which never runs. |
| Devtools (email testing) | `packages/devtools/` (`server.ts`, `src/`) | 🟢 (standalone) | Mailpit/Mailhog-style **testing** tool: Bun HTTP server, **own in-memory store**, chaos mode, webhooks, HTML/spam/link checks. **Not** end-user webmail; does **not** talk to the Zig server. |
| Devtools UI templates | `packages/devtools/pages/app.stx` (58KB), `home.stx` (51KB) | 🟢 (in devtools) | The only place `stx` is actually wired, via `bun-plugin-stx`. Excellent design reference. |
| Static mockups | `examples/webmail.html` (38KB), `examples/devtools.html` (35KB) | ⚪ | Standalone design demos. Not served by anything. |
| Browser auth/session | — | 🔴 | No cookie/JWT/session login flow. `WebmailSession` struct exists but is never populated. What *does* exist: SMTP/IMAP `AUTH`, HTTP **Digest** auth + `NonceManager` (RFC 7616) in `auth.zig`, `password.zig` (Argon2id), `csrf.zig` — all server-protocol auth, not browser sessions. |
| `crosswind` CSS | — | 🔴 | **Not installed** in any `package.json` (verified via grep). CLAUDE.md aspiration only. No Tailwind config. |
| Live HTTP listener | — | 🔴 | **No HTTP/HTTPS port is opened at all.** `main.zig` spawns only SMTP/IMAP/CalDAV/ManageSieve threads. Neither `api.zig` nor `webmail.zig` is referenced from `main.zig`. |

\* "Live" for `api.zig`/`admin.html` is conditional on it being enabled in config.

### What production actually runs
`main.zig`'s `serve` command starts only mail-protocol listeners in their own
threads: **SMTP (25), SMTPS (465), Submission (587), IMAP/IMAPS (143/993),
CalDAV (8008/8009), ManageSieve (4190)**. There is **no HTTP listener of any
kind** — `grep` for `APIServer`/`webmail`/`WebmailHandler` in `main.zig` returns
nothing. Both `api.zig` and `webmail.zig` are **complete but orphaned**: they
compile and have tests, but nothing instantiates or routes to them. So today
there is **zero HTTP surface** to build a UI on — wiring one up is task #1 of the
backend work.

### Implications for this plan
1. We are **near-greenfield for a *real* webmail**, but with strong assets:
   - A **data-model skeleton** in `webmail.zig` (`WebmailMessage`, `FolderType`,
     `EmailAddress`, threads, signatures, contacts) worth reusing.
   - **Visual references** (`examples/webmail.html`, devtools `app.stx`,
     `serveMainPage`).
2. The four hardest missing pieces, in rough dependency order:
   1. **Browser auth/session layer** (login → secure cookie/token → CSRF).
   2. **A wired HTTP listener** that routes to a webmail handler.
   3. **Real data**: replace mock handlers with Maildir + SQLite-backed queries
      that stay consistent with IMAP flag semantics.
   4. **A real compose → delivery-queue/SES send path.**
3. **Tooling decision needed** (see [Open Questions](#open-questions-decisions)):
   `crosswind` is not installed and `stx` only runs inside devtools' Bun setup.

---

## Decisions Locked In

From scoping discussion:

| Decision | Choice | Notes |
|---|---|---|
| **Scope (v1)** | **Webmail client** (end-user inbox) | Admin dashboard deferred; can grow on same shell later. |
| **Frontend stack** | **stx + crosswind** | Per CLAUDE.md. Requires installing/wiring crosswind (currently absent). |
| **Production serving** | **Decide later** | Build frontend as its own package now; choose embed-in-Zig vs. static-assets vs. Bun sidecar at [Phase 9](#phase-9--production-serving--deployment). |

---

## Target Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Browser                                                            │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │  Webmail SPA  (packages/webmail)                               │ │
│  │  stx templates + crosswind CSS + signals/composables          │ │
│  │  3-pane: folders │ message list │ reading pane + compose modal │ │
│  └───────────────┬──────────────────────────────────────────────┘ │
└──────────────────┼─────────────────────────────────────────────────┘
                   │ HTTPS (JSON over fetch), session cookie + CSRF
                   ▼
┌──────────────────────────────────────────────────────────────────┐
│  Zig mail server (packages/zig)                                    │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │  HTTP listener (new/expanded)                                  │ │
│  │   ├─ /webmail/*        → Webmail API (real data)              │ │
│  │   ├─ /webmail/auth/*   → session login/logout (NEW)          │ │
│  │   └─ static assets     → built SPA (prod, if embedded)        │ │
│  └───────┬───────────────────────────┬──────────────────────────┘ │
│          │                           │                              │
│   ┌──────▼───────┐          ┌────────▼─────────┐                  │
│   │ SQLite       │          │ Maildir          │                   │
│   │ users, UIDs, │          │ /opt/mail/mail/  │                   │
│   │ sessions(NEW)│          │ {user}/{cur,new} │                   │
│   └──────────────┘          └──────────────────┘                  │
│          │                                                          │
│   ┌──────▼───────────────────────────────────────────┐           │
│   │ Delivery queue → SES / SMTP (existing send path)  │           │
│   └───────────────────────────────────────────────────┘          │
└──────────────────────────────────────────────────────────────────┘
```

### Key architectural principles
- **The browser never speaks IMAP/SMTP.** It speaks a small JSON HTTP API. The
  Zig server is the only thing that touches Maildir/SQLite/queue.
- **Maildir is the source of truth for messages & flags.** The webmail API must
  read/write Maildir filenames (`:2,FLAGS`) so state stays consistent with what
  Apple Mail sees over IMAP. (See CLAUDE.md "IMAP flag persistence".)
- **Reuse, don't reinvent, the send path.** Compose must funnel into the existing
  delivery queue / SES integration, not a new SMTP client.
- **Frontend is a separate package** (`packages/webmail`) regardless of how it's
  served in prod, so we can iterate with hot reload against a dev proxy.
- **Security is a first-class phase**, not an afterthought (HTML sanitization,
  CSP, session hardening, CSRF, rate limiting).

### Proposed new/changed layout
```
packages/
├── webmail/                    # NEW — frontend SPA (stx + crosswind)
│   ├── package.json
│   ├── bunfig.toml             # linker = "hoisted"; bun-plugin-stx
│   ├── crosswind.config.*      # crosswind setup
│   ├── pages/                  # stx templates (shell, login, inbox, message, compose)
│   ├── src/
│   │   ├── api/                # typed client for /webmail/* (reuse/extend packages/ts)
│   │   ├── components/         # message-list, folder-tree, reading-pane, composer
│   │   ├── composables/        # auth, mailbox state, signals
│   │   └── styles/
│   └── dev-server / proxy config → packages/zig API
└── zig/src/
    ├── api/
    │   ├── webmail.zig         # REWORK — wire in + replace mock data with real
    │   ├── webmail_session.zig # NEW — browser session/cookie/CSRF for webmail
    │   └── http.zig / api.zig  # wire an always-available HTTP listener path
    ├── storage/                # add sessions table + Maildir read/query helpers
    └── auth/                   # reuse password.zig, csrf.zig
```

---

## Phases

Each phase is independently shippable and ends with a demoable increment.
Estimates are rough (calendar weeks, one engineer). Treat the **acceptance
criteria** as the definition of done.

### Phase 0 — Foundations & decisions  ·  ~3–4 days
Set up the skeleton and resolve the open architectural choices so later phases
don't churn.

**Tasks**
- [ ] Resolve [Open Questions](#open-questions-decisions): prod serving model,
      crosswind setup approach, session storage location.
- [x] Scaffold `packages/webmail` (Bun + `bun-plugin-stx`, `bunfig.toml` with
      `linker = "hoisted"`). stx layout: `pages/`, `layouts/`, `partials/`,
      `functions/`, `public/` + `stx.config.ts`.
- [x] Stand up a **dev server with a proxy** to the Zig HTTP API (`server.ts`
      uses `bun-plugin-stx/serve` + its `onRequest` hook to proxy `/webmail/*`;
      unreachable backend returns a labelled 502). Verified: pages, login, static
      asset, and proxy all respond.
- [x] Decide the **JSON API contract** shape — drafted in [API Contract](#api-contract-draft);
      typed client stub at `functions/useApi.ts`.
- [x] CI: lint clean with **pickier** (`bunx --bun pickier .`).
- [ ] Install + wire **crosswind**; produce a one-screen "design system" page
      (colors, type scale, spacing, buttons, inputs) so the look is decided early.
      *(Currently placeholder CSS in `public/styles.css` — see note below.)*
- [x] Add `dev:webmail` / `build:webmail` scripts to `pantry.jsonc`.

**Acceptance**
- ✅ `cd packages/webmail && bun run dev` serves the placeholder pages and proxies
  `/webmail/*` to the Zig server (labelled 502 until Phase 2 — expected).

**Notes / deviations from plan**
- The `bun-plugin-stx/preload` entry **crashes** under Bun 1.3
  (`build.config.root` undefined), so we do **not** preload it. Dev uses the
  plugin's programmatic `serve()` instead (`bun server.ts`). `bun run pages` runs
  the bundled `serve` bin as a fallback.
- stx uses **Blade-style** layout composition (`@extends` / `@section('content')`
  / `@yield('content')`, `@include('Partial')`), **not** `<slot />`. Pages set a
  `meta` object in `<script>` for title/description.

**Risks:** crosswind integration is unproven here — timebox it; fall back to a
documented decision if it fights the toolchain.

---

### Phase 1 — Backend: browser auth & sessions  ·  ✅ DONE
The webmail can't do anything per-user without authenticated browser sessions.

**Tasks**
- [x] `webmail_sessions` table in SQLite (session_id, username, email,
      csrf_secret, created/last_activity/expires, ip, user-agent). Migration + CRUD.
- [x] `webmail_session.zig`: create/validate/revoke sessions; `HttpOnly`,
      `SameSite=Lax`, `Secure` cookies; sliding idle expiry; 256-bit tokens.
- [x] `POST /webmail/auth/login` — verifies via `AuthBackend` (Argon2id), mints session.
- [x] `POST /webmail/auth/logout` — revokes session (server-side + clears cookie).
- [x] `GET /webmail/auth/me` — current user info.
- [x] CSRF: per-session secret issued; same-origin check on logout. (Per-action
      CSRF *token enforcement* on mailbox mutations deferred to Phase 5, when
      those endpoints exist.)
- [x] Rate-limit login per IP (429) via `auth/security.zig` RateLimiter.
- [x] Login timing equalized (dummy Argon2 on unknown/disabled user) — no
      username enumeration.

**Acceptance** ✅ verified end-to-end with `curl`: login→cookie, `/auth/me`,
logout invalidation, bad-password 401, rate-limit 429, cross-origin logout 403.

**Note:** Fixed a pre-existing bug — `users.digest_ha1` was SELECTed but never
created, so every credential check failed on a fresh DB. Added the migration.

---

### Phase 2 — Backend: HTTP wiring + real read path  ·  ✅ DONE
Make the webmail API live and back it with **real mail** from Maildir + SQLite.

**Tasks**
- [x] HTTP listener (`webmail_http.zig`) routing `/webmail/*`, config-gated via
      `SMTP_ENABLE_WEBMAIL` (off by default). New module, not the old dead
      `WebmailHandler`; thread-per-conn mirroring the IMAP accept loop.
- [x] **Folders:** real folders + unread/total counts (`webmail_maildir.zig`).
- [x] **Message list:** reads Maildir `new`/`cur`, parses From/To/Subject/Date,
      flags from `:2,FLAGS`, paginated, newest-first; JSON flag mapping.
- [x] **Message detail:** headers + MIME parse → text + html parts + attachment
      metadata. Wrote a minimal MIME parser (multipart, base64/QP, RFC 2047).
- [x] **UID consistency:** assigns UIDs via the shared `imap_uids` table in
      oldest-first order (matching IMAP `syncUids`) — verified identical mapping.
- [ ] **Attachment download:** metadata is returned; streaming the bytes by id
      is deferred to Phase 4/6 (reading-pane work).

**Acceptance** ✅ verified end-to-end: logged-in user sees their real INBOX
(counts + list) and opens a real message (headers + text + html + attachment
metadata) via the API; path-traversal folders rejected (400); missing UID 404.

**Note:** Also fixed a pre-existing macOS/BSD socket bug (`SOCK_CLOEXEC` in the
`socket()` type arg) that prevented the server binding anywhere but Linux.

---

### Phase 3 — Frontend: app shell & auth UI  ·  ~1 week
**Tasks**
- [ ] App shell with the 3-pane layout (folder sidebar │ list │ reading pane),
      responsive collapse for mobile.
- [ ] Client-side routing (folder / message / compose views).
- [ ] Login + logout pages wired to Phase 1 endpoints; session-expiry handling
      (redirect to login on 401).
- [ ] Typed API client (extend `packages/ts` or a local `src/api/`) used by all
      views; central CSRF token handling.
- [ ] Loading / empty / error states as reusable components.

**Acceptance**
- Log in through the UI, land on an (empty-state) inbox shell, refresh keeps the
  session, logout returns to login.

---

### Phase 4 — Frontend: reading mail  ·  ~1.5 weeks
**Tasks**
- [ ] Folder tree with live unread counts.
- [ ] Message list: virtualized/paginated, sender/subject/snippet/date, unread &
      flagged indicators, multi-select.
- [ ] Reading pane: sanitized HTML render in a **sandboxed iframe**, text
      fallback toggle, full-header view, attachment chips with download.
- [ ] Basic search box (subject/from/body) hitting the read API.
- [ ] Keyboard navigation (j/k, enter, etc.) — nice-to-have within phase.

**Acceptance**
- A user can browse folders, scroll/paginate a real inbox, open messages with
  correctly rendered (and safely sandboxed) content, and download attachments.

**Risks:** HTML email sanitization is security-critical — see [Phase 8](#phase-8--security-hardening).
Do a minimal-but-correct sanitize here; harden later.

---

### Phase 5 — Flags & message actions (persisted)  ·  ~1 week
**Tasks**
- [ ] Backend: write endpoints to set flags (read/unread, flag/star, answered),
      delete (→ Trash), move between folders — implemented by **renaming Maildir
      files** (`:2,FLAGS`) and updating any SQLite UID/metadata so **IMAP stays
      consistent**.
- [ ] Frontend: wire actions (toolbar + context menu + bulk on multi-select),
      optimistic UI with rollback on error.
- [ ] Verify round-trip: action in webmail → visible in Apple Mail and vice versa.

**Acceptance**
- Marking read/flag/delete/move in webmail is reflected in Apple Mail (and the
  reverse), proving Maildir/IMAP consistency.

**Risks:** This is the consistency crux. Add integration tests against a Maildir
fixture; document the flag mapping precisely.

---

### Phase 6 — Compose & send  ·  ~1.5–2 weeks
**Tasks**
- [ ] Composer UI: to/cc/bcc (with validation), subject, rich + plain body,
      attachment upload (progress), reply / reply-all / forward (quote + headers),
      `In-Reply-To`/`References` for threading.
- [ ] Backend: `POST /webmail/api/compose` builds a correct MIME message and
      **submits it to the existing delivery queue / SES path** (not a new client).
- [ ] **Save to Sent** (append to Maildir `Sent` after send).
- [ ] **Drafts:** save/update/delete drafts in the `Drafts` folder.
- [ ] Attachment upload storage + size/type limits (reuse `attachment_storage`).
- [ ] DKIM/SPF correctness: ensure outbound webmail mail is signed exactly like
      the existing send path (reuse, don't duplicate).

**Acceptance**
- Send a real email from webmail that is delivered (DKIM-signed), appears in
  Sent, and a reply threads correctly. Drafts persist across sessions.

**Risks:** Outbound auth/signing must match production exactly; test against a
real recipient + check headers.

---

### Phase 7 — Search & organization polish  ·  ~1 week
**Tasks**
- [ ] Integrate the real **search index** (api.zig referenced
      `/api/search`, `/api/search/rebuild`, `search/stats`) instead of naive scan.
- [ ] Advanced search (from/to/subject/has-attachment/date range/folder).
- [ ] Signatures, templates, contact groups, scheduled send — port the
      `webmail.zig` managers from mock to persistent storage **as desired**
      (each is optional; prioritize by user value).
- [ ] Settings page (display density, signature default, etc.).

**Acceptance**
- Search returns relevant real results quickly; at least signatures + a settings
  page are persisted and usable.

---

### Phase 8 — Security hardening  ·  ~1 week (overlaps earlier phases)
> Security work is seeded in earlier phases; this phase is the dedicated audit.

**Tasks**
- [ ] **HTML email sanitization**: strict allow-list; render in sandboxed iframe
      with a restrictive `sandbox` attr; block remote content by default with a
      "load remote images" opt-in (privacy + tracking protection).
- [ ] **CSP** headers for the SPA; no inline-script reliance where avoidable.
- [ ] Session hardening review: rotation, idle + absolute timeouts, revoke-all,
      cookie flags, fixation protection.
- [ ] CSRF on every mutating endpoint; verify Origin/Referer.
- [ ] Rate limiting on auth + send + search.
- [ ] Attachment handling: content-type sniffing safety, `Content-Disposition:
      attachment`, no inline execution.
- [ ] Run `/security-review` on the diff; address findings.
- [ ] Authorization: ensure a user can only ever access **their own** mailbox
      (path/UID scoping) — write tests that attempt cross-user access.

**Acceptance**
- Security review passes; manual XSS attempts via crafted emails are blocked;
  cross-user access is impossible.

---

### Phase 9 — Production serving & deployment  ·  ~3–5 days
Resolve the deferred "how is it served" decision and ship it.

**Options to choose from (decide in Phase 0 or here):**
- **A. Embed built assets in the Zig binary** (`@embedFile` the built SPA) →
  single binary, simplest deploy, matches `serveMainPage` precedent.
- **B. Serve static assets from disk** next to the binary (`/opt/mail/webmail/`).
- **C. Bun sidecar** serving the SPA, reverse-proxied to the Zig API.

**Tasks**
- [ ] Implement the chosen serving model + production build pipeline.
- [ ] TLS already exists (Let's Encrypt at `mail.stacksjs.com`) — choose the
      webmail hostname/path (e.g. `https://mail.stacksjs.com/` or a subdomain).
- [ ] Deploy via the existing **AWS SSM** flow (cross-compile `x86_64-linux`,
      S3 upload, SSM swap, restart) per CLAUDE.md.
- [ ] Observability: add webmail health/metrics to the Discord monitor + metrics.
- [ ] Runbook: how to deploy/rollback the webmail.

**Acceptance**
- Webmail reachable over HTTPS in production against a real mailbox, deployed via
  the documented SSM pipeline.

---

### Phase 10 — Polish, a11y, mobile, tests  ·  ~1 week (ongoing)
**Tasks**
- [ ] Accessibility pass (focus, ARIA, keyboard, contrast).
- [ ] Mobile/responsive refinement.
- [ ] Performance (list virtualization, lazy bodies, caching).
- [ ] E2E tests for the critical flows (login → read → flag → reply → send).
- [ ] Empty/error/offline states; toasts; undo for destructive actions.

**Acceptance**
- Lighthouse/a11y baseline met; E2E suite green; usable one-handed on mobile.

---

## API Contract (draft)

> The interface both frontend and backend build against. Refine in Phase 0.
> All under `/webmail`. JSON in/out. Session cookie + `X-CSRF-Token` on mutations.

**Auth**
- `POST /webmail/auth/login` `{username, password}` → sets cookie, `{user}`
- `POST /webmail/auth/logout` → `204`
- `GET  /webmail/auth/me` → `{user}` | `401`

**Folders**
- `GET /webmail/api/folders` → `[{id, name, type, unread, total}]`

**Messages**
- `GET  /webmail/api/messages?folder=&page=&limit=&q=` →
  `{items:[{uid, from, to, subject, snippet, date, flags:{seen,flagged,answered,draft,deleted}, hasAttachments}], total, page}`
- `GET  /webmail/api/messages/:uid` →
  `{uid, headers, html, text, attachments:[{id, filename, size, contentType}], flags}`
- `GET  /webmail/api/messages/:uid/attachments/:id` → binary stream
- `PUT  /webmail/api/messages/:uid` `{flags?, folder?}` → updated message (flag/move)
- `DELETE /webmail/api/messages/:uid` → move to Trash (or purge if already Trash)

**Compose / drafts**
- `POST /webmail/api/compose` `{to, cc, bcc, subject, html, text, attachments[], inReplyTo?}` → `{queued:true, id}`
- `POST /webmail/api/drafts` / `PUT /webmail/api/drafts/:id` / `DELETE /webmail/api/drafts/:id`
- `POST /webmail/api/attachments` (multipart) → `{id, filename, size}`

**Search / extras (later phases)**
- `GET /webmail/api/search?q=&from=&to=&hasAttachment=&since=&before=`
- `GET/POST /webmail/api/signatures`, `/templates`, `/groups`, `/scheduled`

> The existing `webmail.zig` already declares most of these routes
> (`handleApiGet/Post/Delete`, ~ln 317–390) — reuse the shapes where sensible,
> but **replace the mock bodies with real data**.

---

## Open Questions / Decisions

| # | Question | Options | Default leaning |
|---|---|---|---|
| 1 | Production serving model | Embed in binary / static on disk / Bun sidecar | **Embed** (single-binary deploy, matches precedent) — confirm in Phase 0 |
| 2 | crosswind integration | Confirm it works with stx/Bun here | Timebox in Phase 0; document fallback |
| 3 | Webmail HTTP: always-on or config-gated? | Always-on / gated like `api.zig` | Gated initially, flip on when ready |
| 4 | Hostname/path | `mail.stacksjs.com/` vs `webmail.` subdomain | Decide before Phase 9 |
| 5 | Reuse `webmail.zig` vs. fresh handler | Revive 4203-ln file / start clean & port types | Reuse types, rework handlers against real data |
| 6 | Rich text editor | Build vs. library | Decide in Phase 6 |
| 7 | Session storage | SQLite `sessions` table (chosen) | SQLite |

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Maildir/IMAP flag inconsistency | Webmail & Apple Mail disagree | Treat Maildir as source of truth; integration tests in Phase 5; reuse UID mapping |
| HTML email XSS | Account/data compromise | Sandboxed iframe + strict sanitizer + CSP; dedicated Phase 8 + `/security-review` |
| Outbound mail not DKIM-signed correctly | Deliverability / spoofing | Reuse existing delivery/queue/SES + DKIM path; verify headers on a real send |
| crosswind not actually integrable | Frontend churn | Timebox in Phase 0; fallback to documented alternative |
| `webmail.zig` mock code mistaken for working | False sense of progress | This doc + tests; every handler must be proven against real data |
| Zig 0.16-dev breaking changes / compat layers | Build friction | Follow CLAUDE.md "Zig 0.16 Specifics"; use `*_compat` modules |
| Scope creep (calendar/contacts/admin) | Slips v1 | Non-goals are explicit above; defer |

---

## Reference: key files

- `packages/zig/src/api/webmail.zig` — handler skeleton + embedded SPA + data
  model (reuse types; rework handlers).
- `packages/zig/src/api/api.zig` — admin HTTP server + router patterns to follow.
- `packages/zig/src/api/admin.html` — existing served-HTML precedent.
- `packages/zig/src/auth/{auth,password,csrf}.zig` — credential verification,
  Argon2id, CSRF primitives to build sessions on.
- `packages/zig/src/storage/` — SQLite layer (add `sessions`, Maildir helpers).
- `packages/devtools/{server.ts,pages/app.stx}` — stx wiring reference + design.
- `examples/webmail.html` — visual/design reference.
- `packages/ts/src/index.ts` — existing TS package (deploy/config helper; extend
  or sibling a typed API client).
- `CLAUDE.md` — Maildir/flag semantics, Zig 0.16 specifics, SSM deploy, tooling
  (pickier/stx/crosswind/better-dx) conventions.

---

## Changelog
- 2026-05-29 — Initial plan + current-state inventory.
