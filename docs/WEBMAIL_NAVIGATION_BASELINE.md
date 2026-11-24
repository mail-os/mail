# Webmail navigation baseline

This record verifies the native workflow in [#34](https://github.com/mail-os/mail/issues/34).
The candidate is the ReleaseFast native binary built from `761ae9c` in
[draft PR #96](https://github.com/mail-os/mail/pull/96). The documented
pilot and public deployment gates are [#83](https://github.com/mail-os/mail/issues/83)
and [#85](https://github.com/mail-os/mail/issues/85).

## Published Mail

The macOS ARM64 archive for [v0.3.26](https://github.com/mail-os/mail/releases/tag/v0.3.26)
matched its GitHub SHA-256 digest. It accepted a real SMTP message for a
disposable local mailbox. Chromium signed in and opened the original message
at 1440 × 940 and 390 × 844 over loopback HTTP. Opening the message took
65 ms and 68 ms respectively. The `/calendar` and `/shared` routes returned
HTTP 404. The tagged guide also documents draft autosave, bulk actions with Undo,
search, conversation grouping, attachments, Undo Send, and password recovery.
[Published webmail guide](https://github.com/mail-os/mail/blob/v0.3.26/WEBMAIL.md#mailbox-experience)

## Candidate walkthrough

Each desktop or phone profile provisions a fresh disposable mailbox and uses
Mail's real HTTPS listener. SMTP sends the Inbox, first-contact, newsletter,
receipt, shared inbox and invitation messages. IMAP populates a custom folder
and CalDAV writes the scheduled events. The browser uses the daemon routes directly.

- **Inbox and folders** show the primary account and an IMAP-created Design
  reviews folder. The mobile Mailboxes drawer gives access to the same groups.
- **Sender Review** holds two verified first contacts. Allow releases one to
  Inbox. Decline keeps the other in the Declined view and out of Inbox.
- **Newsletters and Receipts** display category views for actual SMTP messages.
  The fixture uses a List-ID newsletter and a receipt with an attachment.
- **Follow-up and Saved** both show the message after it is marked from the
  reader.
- **Calendar** displays the CalDAV event. The invitation reader sends an
  acceptance. The organizer independently receives a matching iCalendar
  reply with `PARTSTAT=ACCEPTED`.
- **Shared inboxes** assigns a proof to a teammate. A separate signed-in
  browser session opens the same message and sees the assignment.
- **Triage** opens the next unread message, archives it and advances, then
  undoes the archive. The phone run uses emulated touch input.

The candidate keeps folder navigation, collections and workflows in named
sidebar groups. The desktop retains the reader beside the message list.
The phone uses the mailbox drawer, full-width list and separate reader.
Calendar and Shared inboxes open dedicated workspaces. The phone batch reader
uses several action rows above the message. [#139](https://github.com/mail-os/mail/issues/139)
tracks continuous reading and keeping actions within reach.

## Reproduce

From the repository root on a machine with Zig, Bun, Node.js 20+, Python 3
and OpenSSL installed.

```sh
bun install --frozen-lockfile
bun run playwright install chromium firefox webkit
(cd packages/zig && zig build -Doptimize=ReleaseFast)
python3 scripts/test-webmail-navigation.py packages/zig/zig-out/bin/mail /tmp/mail-navigation --revision "$(git rev-parse HEAD)"
```

The Linux browser job uploads `webmail-browser-screenshots/navigation`
with the screenshots and timing JSON. Desktop uses 1440 × 940 at 1× in
light mode. Phone uses 390 × 844 at 2× in dark mode. Each timing starts
before the navigation or action and ends once the expected result is
visible. It includes browser automation, rendering and loopback service
time. These samples come from one run per browser and layout on macOS ARM64.
The production search and p95 performance targets are tracked in
[#71](https://github.com/mail-os/mail/issues/71).

## Timing samples in milliseconds

| Workflow | Chromium desktop | Chromium phone | Firefox desktop | Firefox phone | WebKit desktop | WebKit phone |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Next unread | 169 | 231 | 165 | 291 | 140 | 98 |
| Archive and advance | 246 | 304 | 193 | 189 | 273 | 144 |
| Undo archive | 72 | 155 | 128 | 71 | 74 | 83 |
| Open Sender Review | 74 | 143 | 136 | 134 | 75 | 103 |
| Approve first contact | 113 | 130 | 97 | 140 | 122 | 121 |
| Open Newsletters | 81 | 142 | 116 | 142 | 79 | 105 |
| Open Receipts | 67 | 185 | 103 | 195 | 62 | 89 |
| Open Follow-up | 97 | 199 | 154 | 147 | 91 | 102 |
| Open Saved | 68 | 182 | 94 | 162 | 67 | 93 |
| Open the custom folder | 69 | 141 | 122 | 444 | 70 | 100 |
| Send RSVP and show confirmation | 837 | 847 | 889 | 924 | 821 | 817 |
| Open Calendar and show the event | 375 | 533 | 357 | 598 | 397 | 298 |
| Open the shared inbox message | 409 | 515 | 424 | 665 | 434 | 429 |
| Assign to a teammate | 25 | 25 | 28 | 49 | 29 | 29 |

## Capability coverage

Benchmark scope follows the public feature list and relevant Calendar, terminal, assistant, and release notes, reviewed November 24, 2026. [HEY features](https://www.hey.com/features/) · [Release notes](https://www.hey.com/new/) · [Calendar](https://www.hey.com/calendar/) · [CLI and TUI](https://www.hey.com/agents/) · [Assistants](https://www.hey.com/ai/)

## Mail and teams

| Capability | Mail evidence in #96 | Limits and tracking |
| --- | --- | --- |
| First-contact decisions, temporary access, and Junk feedback | **Sender Review** holds first contact, groups by sender, shows verification and destination, and supports Allow, Allow and reply, Decline, and recovery. Temporary invitations are address-bound, expiring, and revocable. **Mark junk**, Not junk, and Undo update the current message. Future routing preferences apply to verified senders in that mailbox. `scripts/test-sender-review.py`, `scripts/test-webmail-junk.py`. | The addressing model uses a verified sender invitation. Check whether approval should optionally mark already-previewed messages read. Cleanup of held and Junk mail needs its own scope and recovery decision. [#37](https://github.com/mail-os/mail/issues/37) · [#44](https://github.com/mail-os/mail/issues/44) · [#77](https://github.com/mail-os/mail/issues/77) |
| Focused Inbox, Newsletters, Receipts, and sender bundles | **Automatic sorting** and sender rules route verified mail after Sender Review. **Newsletters** and **Receipts** are IMAP folders with sender bundles and Unread/Previously read sections. Newsletters use an expanded reader. Receipts keep previews compact. `scripts/test-mail-categories.py`, `scripts/webmail-browser.mjs`. | Inbox uses unread indicators and Next unread. Grouped read history and folder-wide mark read are useful triage follow-ups. Category bundling can be evaluated separately for ordinary Inbox senders. [#38](https://github.com/mail-os/mail/issues/38) · [#40](https://github.com/mail-os/mail/issues/40) |
| Rapid reading and triage | **Next unread** crosses pages, **Read selected** advances through a batch, and archive/trash-and-next, bulk read/move/flag, Undo, shortcuts, and the mobile mailbox chooser keep actions close to the reader. `packages/webmail/ux-e2e.test.ts`, `scripts/webmail-browser.mjs`. | Sequential reader with a shared action toolbar. Continuous reading and inline triage are tracked in [#139](https://github.com/mail-os/mail/issues/139). |
| Follow-up, Saved, snooze, mute, and no-reply reminders | **Follow-up** supports Next reply and can clear after successful delivery. **Saved** keeps a specific message across moves. Snooze wakes on its deadline or a new human reply. Mute hides the conversation in webmail and suppresses notices. **Remind me if no reply** is available in Sent. `scripts/test-mail-attention.py`. | Snoozed and muted messages remain in All mail and IMAP. A persistent top-of-Inbox return or clearing Saved on send would be new behavior. [#39](https://github.com/mail-os/mail/issues/39) |
| Reader protection and quiet notifications | Formatted views block remote images by default, including batch reading. Per-message image loading and plain text are available. Browser notices are opt-in, generic, and configurable by thread or verified sender, with mute and snooze respected. `scripts/test-mail-notifications.py`, `scripts/webmail-browser.mjs`. | Notices rely on signed-in, open webmail. Track background delivery, deduplication, and privacy separately from reader consent. Tracker identification would be a separate capability. [#41](https://github.com/mail-os/mail/issues/41) · [#78](https://github.com/mail-os/mail/issues/78) |
| Visual personalization and mobile clients | Responsive webmail, light and dark appearances, grouped navigation, and **Install Mail** browser guidance. `scripts/webmail-browser.mjs` covers mobile controls and the install entry point. | The web app requires a connection. Inbox cover art, native widgets, and offline reading are candidates for separate product decisions. [#92](https://github.com/mail-os/mail/issues/92) · [#95](https://github.com/mail-os/mail/issues/95) · [#78](https://github.com/mail-os/mail/issues/78) |
| Private notes, clips, collections, subjects, and manual grouping | **Private tools** stores conversation notes, text clips, personal subjects and collections. **Group selected** joins conversations with Undo. Original headers remain intact and private metadata stays in webmail. `scripts/test-webmail-private.py`. | The current editor stores text. A mailbox-wide clips view, pinned notes, and privately attached note files each need separate UX and storage scope. Teammate sharing takes an explicit grant. [#43](https://github.com/mail-os/mail/issues/43) · [#51](https://github.com/mail-os/mail/issues/51) |
| Contact notes and groups | **Contacts** edits CardDAV cards, notes, and groups, with revision checks and an Email group draft. `scripts/test-webmail-contacts.py`. | Address book search matches names and email addresses. Track matching note text with the same account scope. [#44](https://github.com/mail-os/mail/issues/44) |
| Search and Attachments | Private index, folder/sender/recipient/date/status/flag/file filters, and a cross-folder **Attachments** view with source navigation and checked downloads. `scripts/test-webmail-index.py`. | Mail has its own [indexed search benchmark](https://github.com/mail-os/mail/blob/761ae9c/WEBMAIL.md#native-indexed-search-benchmark). Track recent queries and multi-file download as separate UX. [#42](https://github.com/mail-os/mail/issues/42) · [Performance gates #71](https://github.com/mail-os/mail/issues/71) |
| Large files | **Add file link** creates a recipient-accessible, expiring download with original bytes and owner revocation. Limits include 24 MiB per file, 20 active links, and 96 MiB in total, subject to quota. `scripts/test-webmail-file-links.py`. | Validate expected file sizes and retention before increasing the cap. [#75](https://github.com/mail-os/mail/issues/75) |
| Snippets, scheduled send, Undo Send, and bulk replies | **Writing tools** stores snippets and signatures. **Send later** and the durable **Outbox** handle review, edits, cancellation, and uncertain delivery. **Reply separately** previews each recipient and queues independent replies for 2–20 messages. `scripts/test-webmail-writing-tools.py`, `scripts/test-webmail-scheduled-send.py`, `scripts/test-webmail-outbox-recovery.py`, `scripts/test-webmail-batch-replies.py`. | Queue cancellation runs up to dispatch. Recipient results remain separate. Merge and release tracking sit with [#79](https://github.com/mail-os/mail/issues/79), [#94](https://github.com/mail-os/mail/issues/94), and [#100](https://github.com/mail-os/mail/issues/100). |
| External From, forwarding, and combined accounts | **External From addresses** require operator approval and mailbox-owner verification. **Combined inbox** links up to four Mail accounts in one browser, labels each source, and rechecks each action against it. **Forwarding** verifies the destination and supports filters. `scripts/test-webmail-external-senders.py`, `scripts/test-webmail-combined.py`, `scripts/test-webmail-forwarding.py`. | External sending uses provider SMTP with STARTTLS and provider credentials. Track provider OAuth/API delivery separately. Aggregation covers authenticated Mail accounts. [#76](https://github.com/mail-os/mail/issues/76) · [#77](https://github.com/mail-os/mail/issues/77) · [#118](https://github.com/mail-os/mail/issues/118) · [#119](https://github.com/mail-os/mail/issues/119) |
| Vacation replies and retention | **Vacation reply** supports schedules, verified sender checks, loop prevention, and persisted cooldown. **Automatic cleanup** previews one rule for selected folders, moves eligible mail to Trash, and allows recovery. `scripts/test-webmail-vacation.py`, `scripts/test-webmail-retention.py`. | Cleanup starts off and retains unread and workflow-protected messages. Trash counts toward storage until deletion. [#44](https://github.com/mail-os/mail/issues/44) · [#77](https://github.com/mail-os/mail/issues/77) |
| Team threads and collections | Teammates can see selected messages, private team comments, and explicitly granted attachments. Thread grants may follow qualifying verified replies, including eligible webmail, SMTP/IMAP, EWS, and ActiveSync sends. Shared collection entries are explicit. `scripts/test-webmail-team-threads.py`. | Followed text is capped at 40 replies per grant. Collection followers get only explicitly added messages. [#51](https://github.com/mail-os/mail/issues/51) · [#121](https://github.com/mail-os/mail/issues/121) |
| Shared addresses, handoffs, and workflow stages | **Shared inboxes** covers dedicated addresses, separate access and From grants, assignments, resolve/reopen, and managed stages with verified sender routing. Outbox reserves an original message against duplicate replies. `scripts/test-webmail-{teams,shared-inbox,shared-replies}.py`, `scripts/webmail-browser.mjs`. | Stages apply to a shared Inbox. Personal mail has Follow-up and collections. A personal multi-stage workflow would need its own product decision. [#49](https://github.com/mail-os/mail/issues/49) · [#50](https://github.com/mail-os/mail/issues/50) · [#52](https://github.com/mail-os/mail/issues/52) · [#135](https://github.com/mail-os/mail/issues/135) |
| External links and publishing by email | **Share snapshot** previews an expiring, revocable text link for up to ten selected messages. Sharing a later reply requires another preview and link. `scripts/test-webmail-snapshot-links.py`. | Snapshots exclude images and attachments and never update themselves. A public site, subscriber delivery, and RSS need a separate audience and consent model. [#74](https://github.com/mail-os/mail/issues/74) · [#117](https://github.com/mail-os/mail/issues/117) · [#78](https://github.com/mail-os/mail/issues/78) |
| Account security | Mailbox password sign-in, TLS, password recovery, and scoped, revocable **App passwords** for supported clients. `packages/webmail/recovery.test.ts`, `scripts/test-client-passwords.py`. | Interactive mailbox multi-factor sign-in and recovery are tracked in [#140](https://github.com/mail-os/mail/issues/140). [#44](https://github.com/mail-os/mail/issues/44) · [#58](https://github.com/mail-os/mail/issues/58) |
| Terminal and assistant access | Operator `mail` CLI covers server and mailbox administration, search, backup, and migration. Terminal mail clients use IMAP and submission. **Assistant access** grants named integrations revocable access to selected text and/or draft creation. The owner sends from the regular composer. `scripts/test-webmail-assistant-grants.py`, `scripts/test-mailbox-export.py`. | First-party terminal Mail/Calendar and broad account automation are separate scopes. The assistant API excludes general search, sender review, Calendar, and send. [Client decisions](https://github.com/mail-os/mail/blob/761ae9c/docs/CLIENT_SURFACES.md) · [#78](https://github.com/mail-os/mail/issues/78) · [#120](https://github.com/mail-os/mail/issues/120) |

## Calendar

| Capability | Mail evidence in #96 | Limits and tracking |
| --- | --- | --- |
| Views, calendar search, and time zones | **Calendar** has Day, Week, Month, Year and a 30-day Agenda, plus a date picker, display and event time zones, color-coded calendars, and keyboard date navigation. Search matches event title, location, and description. Day offers a timeline with overlap handling and keyboard and touch creation, alongside the chronological List. `packages/webmail/calendar-dates.test.ts`, `scripts/webmail-browser.mjs`, `scripts/test-webmail-day-timeline.py`. | Time display preferences and restored date or view need separate decisions. Search of personal tools would need explicit scope. [#46](https://github.com/mail-os/mail/issues/46) · [#72](https://github.com/mail-os/mail/issues/72) · [#136](https://github.com/mail-os/mail/issues/136) |
| Free time, day labels, and flexible tasks | **Find free time** returns open intervals for a chosen date, period and minimum duration. Private **Day labels** follow the civil date. **Tasks** can be undated, rescheduled or completed without reserving calendar time. `scripts/test-webmail-calendar-{free-time,day-labels,tasks}.py`. | Availability is a request with explicit inputs. Track passive free-time highlights and week-level task placement if needed. Labels and Tasks use Mail’s private workflow storage. [#72](https://github.com/mail-os/mail/issues/72) · [#80](https://github.com/mail-os/mail/issues/80) |
| Personal Calendar tools | Opt-in **Personal tools** includes countdowns, habit check-ins, a dated journal, manual time logs and compact layout. Private tools support a JSON export/import workflow. `scripts/test-webmail-calendar-tools.py`, `scripts/webmail-browser.mjs`. | Track live timers, event highlights, day photos, Inbox calendar preview, or home-screen widgets independently. Existing tools stay private and use separate export data. [#73](https://github.com/mail-os/mail/issues/73) · [#78](https://github.com/mail-os/mail/issues/78) |
| Recurrence, event details, and reminders | Browser editor supports common repeat intervals, count/end date, individual changes and cancellations, and one editable display alarm. Webmail honors multiple imported display alarms, including supported absolute times, offsets and repeats. `packages/webmail/calendar-recurrence.test.ts`, `packages/webmail/calendar-reminders.test.ts`. | CalDAV handles advanced rules and alarm editing. Track multiple browser-authored alarms, reminder defaults, geographic autocomplete, and ways to deliver reminders outside an open session. [#46](https://github.com/mail-os/mail/issues/46) · [#114](https://github.com/mail-os/mail/issues/114) · [#130](https://github.com/mail-os/mail/issues/130) |
| Invitations, RSVP, and email-to-event | Preview invites, updates and cancellations. Verified organizer mail can save to an owned calendar and accept, tentatively accept or decline through Outbox. **Create event from email** saves a private source backlink. `scripts/test-dav-https.py`, `scripts/webmail-browser.mjs`. | Saving and responding are independent. A later verified revision can supersede an earlier action. External link and alarm privacy is part of the native regression. [#47](https://github.com/mail-os/mail/issues/47) |
| Calendar sharing, imports, and DAV clients | Teammate viewer/editor/free-busy grants, authenticated CalDAV sync, and webmail ICS preview/import/export against the same store. `scripts/test-webmail-calendar-shares.py`, `scripts/test-dav-https.py`, `packages/webmail/calendar-e2e.test.ts`. | Availability-only shares expose busy intervals. Private event details and owner source links stay hidden. External migration uses ICS files and authenticated clients. Verify Google, Outlook, and Apple import/setup journeys. A subscription URL would need separate access and revocation rules. [#45](https://github.com/mail-os/mail/issues/45) · [#48](https://github.com/mail-os/mail/issues/48) · [#80](https://github.com/mail-os/mail/issues/80) · [#112](https://github.com/mail-os/mail/issues/112) · [#113](https://github.com/mail-os/mail/issues/113) |
