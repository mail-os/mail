# Native webmail

The mail executable embeds an stx client and serves the same account and Maildir
used by SMTP and IMAP. Users sign in with their full mailbox address and mail
password. Deployments expose HTTPS through ts-cloud's native rpx integration;
webmail provisioning, aliases, certificate issuance and renewal live in ts-cloud.

## Mailbox experience

- Drafts autosave while the composer remains open. Server acknowledgements drive
  Saving/Saved status; saved recipients, unfinished input, names and attachment
  references survive refresh. Conditional revisions prevent a stale browser tab
  from overwriting another edit. A conflict offers Save a copy or Reload.
- Message selection supports individual rows, Shift ranges and the current page.
  Bulk archive, move, read/unread, flag and Trash return per-message results.
  Recoverable actions offer Undo for 30 seconds, with fresh UIDs on restored moves.
  Permanent deletion requires explicit confirmation and has no Undo.
- Choose **Next unread** to read through the active folder or search, including
  unread messages beyond the current page. It wraps to earlier unread mail when
  it reaches the end. Choose **Read selected** to work through a batch in order.
  Use **Archive & next** or **Trash & next** to continue after filing a message.
  **Keyboard shortcuts** lists the keys for reading, selection, and Undo.
- Local sends are acknowledged after the server records their recipient
  outcomes and reserves storage. If a Maildir write is interrupted, recovery
  finishes the accepted copy. Inbox counts, search indexing, and arrival
  webhooks follow committed Inbox delivery.
- Sender Review groups held messages by sender and shows their verification
  and envelope destination. **Allow sender** releases held mail and sets the
  rule for future verified messages. **Allow and reply** opens an editable
  reply. **Decline sender** sends held and future verified mail to Declined.
  Recover a single message from Declined or edit the sender's rule in Decisions.
- A decision on an unverified copy applies to that message only. New hosted
  mailboxes enable Sender Review when the user completes inbox setup. Existing
  mailboxes can turn it on in Account settings. Turning it off lets new mail
  reach the inbox while preserving the existing review list and decisions.
- **Mark junk** moves one message or a selection into Junk. **Not junk**
  returns messages to their previous folder when it still exists, or to Inbox.
  **Undo** reverses the move and its feedback. The folder and message changes
  are visible in IMAP.
- Junk feedback affects future mail from the same verified sender in your
  mailbox. Marking an unauthenticated message changes only that copy. Not Junk
  can recover a future soft spam classification, subject to Sender Review.
  Malware and SMTP rejections still apply. Ordinary moves do not change the
  sender preference.
- Newsletters and Receipts are mailbox folders shared with IMAP. The web views
  group messages by sender under **Unread** and **Previously read**. Newsletters
  open in an expanded reader. Receipts open with a short preview and attachment
  links, with the full message one click away.
- Formatted mail blocks remote images by default, including during batch
  reading. **Load remote images** applies to the open message until you leave
  it. Images embedded in the message can display offline. **Show plain text**
  switches to the sender's text version, when available. Receipt previews
  display text only.
- Turn on **Browser notifications** in Account and allow the browser prompt.
  A signed-in browser with webmail open can show “You have new mail.” Set
  **Notification rules** in the reader for a thread or verified sender.
  Thread rules take precedence over sender rules. Muted threads and threads
  still snoozed at delivery stay quiet.
- Turn on **Automatic sorting** in Account to file new messages from verified
  senders using mailing-list headers and common receipt subject lines. Sender
  Review runs first. **Move this message** changes the current copy. **Save
  sender rule** applies your chosen folder to future verified mail from that
  sender. Choose **Use account sorting** to clear the rule. The reader shows
  where the message was delivered and why.
- Add a conversation to **Follow-up** and choose **Next reply** to work through
  the queue one conversation at a time. A reply can clear the mark after
  successful delivery. **Saved** keeps the specific message, including when
  the message moves to another folder.
- **Snooze thread** hides the conversation from webmail's Inbox and category
  views until the selected local time or a new reply. **Mute thread** keeps
  the conversation out of those views and suppresses arrival notifications
  until you unmute it. Messages remain available in **All mail** and IMAP.
- In Sent, choose **Remind me if no reply** and pick a deadline in your
  browser's time zone. A reply cancels the reminder. Due reminders appear
  in webmail and can be dismissed there. Automatic replies keep scheduled
  snoozes and reminders in place.
- To/Cc/Bcc use recipient chips, keyboard contact selection and inline validation.
  Suggestions combine the account's CardDAV contacts with recent correspondents.
  Cc/Bcc remain collapsed until requested or restored from an existing draft.
- Search supports folder, sender, recipient, date, message status, flag, and
  attachment filename filters. Mail builds a private SQLite index as needed and
  displays progress while it indexes existing messages. The index checks live
  Maildir files for new, changed, moved, and deleted messages. Filtering and
  conversation grouping precede pagination. Conversations use
  Message-ID/In-Reply-To/References; unrelated messages with the same subject stay
  separate. Expanded members retain their own folder, UID and actions.
- **Attachments** lists matching files across folders. Search by filename or
  use the message filters to narrow the files. Each entry opens its source
  message or downloads the file. Both actions verify the account and message
  revision again.
- Open **Private tools** to add a conversation note, save an excerpt as a
  clip, set a personal subject, or add the conversation to **My collections**.
  The reader shows the original subject alongside a personal subject.
  Collections follow messages across folders. Notes and saved clips remain
  available from the other messages in a conversation after one copy is
  permanently deleted.
- Select messages in a mail list and choose **Group selected** to join their
  conversations. **Undo** removes that grouping for 30 seconds. Personal
  changes stay in webmail. Replies, forwards, and IMAP clients use the
  original messages and headers.
- Attachments upload as binary data with progress, retry, removal and drag/drop.
  Account-scoped staging IDs survive draft recovery and make upload retries
  idempotent. Downloaded attachments retain their original bytes.
- Undo Send holds the message on the server for a configurable interval. It works
  even if the browser closes; cancellation is available before dispatch starts.
  Outbox records delivery results. After a restart, the delivery journal restores
  accepted local recipients and confirmed remote results, then reconciles the Sent
  copy and draft. Remote attempts without a recorded outcome appear as Unknown
  and require review before a manual retry. Confirmed recipients are omitted from
  the retry draft.
- When CalDAV is enabled, Calendar offers day, week, month, and 30-day agenda
  views across all calendars or one selected calendar. Search matches titles,
  locations, and descriptions across dates. Use **Manage calendars** to create
  a calendar or change its color.
- Create, edit, and delete events in the browser. The view and editor each have
  a time zone selector. For all-day events, **Last day** includes that date.
- Recurring dates appear in the calendar using the stored rule, additional
  dates, skips, and moved or cancelled exceptions. Set **Repeat** to create a
  daily, weekly, monthly, or yearly series with an interval, count or last
  date. Timed series keep their local time in the selected time zone.
- Open a date to edit or cancel one occurrence, or choose **Entire series**
  to edit the repeat schedule. Skips and detached occurrence IDs follow a
  compatible series shift, while moved appointments keep their existing
  dates and times. Webmail rejects a schedule that would orphan an exception.
  Use CalDAV for an exception that changes this and all future occurrences
  or for a resource with incompatible start and end time zones.
- Use **Reminder** to set a display alarm at the start of an event or at
  a preset lead time. You can set a different reminder on one occurrence.
  The inbox and calendar show due reminders during a signed-in webmail
  session and catch up on the previous 24 hours when you return. Dismissing
  a reminder applies to that mailbox across webmail sessions.
- Imported display alarms can use absolute times, start or end offsets,
  repeats, and CalDAV acknowledgements. All-day relative alarms use local
  midnight in the browser's configured time zone. CalDAV clients handle
  audio and email alarms.
- Select a calendar and choose **Download .ics** to export the entire calendar,
  including events outside the visible week. The download retains stored
  timezone definitions, recurring exceptions, alarms, and provider properties.
- Choose **Import .ics**, select an existing calendar or enter a new name, and
  preview the file before importing. The preview shows event dates and reports
  individual errors. Imports skip matching event UIDs in the destination.
  Files may contain up to 1,000 events or occurrences and be up to 1 MiB.
- Open a scheduling email to preview an invitation, update, or cancellation.
  The reader shows the organizer, the supplied time zone or all-day dates,
  and the original date of a changed occurrence. It shows **Verified sender**
  when the verified author of the message matches the organizer's address.
  Named calendar attachments remain downloadable.
- When the verified organizer invited your mailbox, choose **Accept**,
  **Tentative**, or **Decline** to email a response. The invitation shows
  delivery status and lets you retry a failed response. Check Outbox for
  delivery details.
- A newer invitation or cancellation from the verified organizer disables
  replies to the affected revision. This applies to messages delivered to
  the mailbox and to approved messages released from Sender Review.
  After an upgrade, Mail checks retained messages with verified delivery
  records for earlier organizer changes. If the reader is still checking
  history, refresh the invitation before replying or applying it to Calendar.
- Choose **Add to Calendar** and select a calendar you own to save a private
  copy of a verified invitation. Choose **Apply to Calendar** or **Apply
  cancellation** on a later message from the same organizer to update that
  copy. Updates can affect one occurrence, a future range, or the series.
  A one-off change at the start of a saved future range keeps the organizer's
  schedule for later occurrences.
  CalDAV clients see each saved change. The saved event links back to the
  original email. The invitation's external links and alarms stay in the
  email. Saving an invitation and sending an RSVP are separate actions.
- Choose **Create event from email** in an open message to start a Calendar
  event with the subject as its title. Edit the title and choose the dates
  before saving. The owner can choose **Open source email** in the saved
  event editor. The private link follows a mailbox move and is hidden once
  the source email is permanently deleted. Shared calendars and ICS exports
  expose event fields without the source link.

### Calendar API

- Message details include `calendar_invites` for recognized `text/calendar`
  `REQUEST` and `CANCEL` parts. Each entry includes the organizer, UID,
  sequence, DTSTAMP, and any original occurrence. Wall times are supplied as
  seconds on the organizer's clock with a separate time zone label. Preview
  reads leave calendar resources and outgoing mail untouched. If
  `calendar_history_pending` is true, refresh the message to obtain the
  invitation actions after Mail checks earlier deliveries. An invitation
  write can return `503 calendar_history_pending` during that check.
- For entries with a corresponding `calendar_rsvps` action, send
  `POST /webmail/api/calendar-rsvp` with the message ETag in `If-Match`
  and the message `reference`, invitation `index`, and `response`
  (`accepted`, `tentative`, or `declined`) in JSON. Use the current
  `previousSendId` to change a response to the same revision or retry a
  definite failure. The response includes the decision and Outbox state.
- A `calendar_invitation_events` action offers the verified invitation's
  Calendar operation. Send `POST /webmail/api/calendar-invitation-event`
  with the message ETag in `If-Match` and its `reference` and invitation
  `index` in JSON. Pass an owned `calendarId` for a new event or the
  target's `eventRevision` to apply a change to an existing event. The
  response returns the event ID, calendar ID, current ETag, and whether
  the operation changed the event.
- `GET /webmail/api/calendar-event-source?reference=…` reads the subject of
  an owned message. Send its reference as `X-Webmail-Source-Message` when
  creating an event in a calendar you own. An owner's event detail includes
  `source_message` while the email is available.
- `GET /webmail/api/calendars` lists the signed-in mailbox's calendars.
  `POST /webmail/api/calendars` creates one from a JSON `name`. Send
  `PATCH /webmail/api/calendars/{id}` with `color` set to a six-digit hex
  color or `null` to update the color.
- `GET /webmail/api/calendar-events?start=…&end=…` lists events in a half-open
  range of up to 366 days. The timestamps are Unix seconds. Pass `calendarId`
  to select one calendar or `q` to search stored event text. A nonempty
  `q` can be used without a range. Each row identifies its `calendar_id`
  and responses are limited to 500 matching records.
  In a date window, `instances=1` includes iCalendar source for recurrence
  candidates. The combined source is limited to 4 MiB.
- `POST /webmail/api/calendar-events` creates an event from `calendarId`,
  `summary` and `time`, with optional `description` and `location`. The
  `time` object contains `start`, optional `end`, and optional `allDay`.
  All-day dates use UTC midnight and the end date is exclusive.
- To create an event from a full iCalendar resource, use
  `POST /webmail/api/calendar-events?calendarId=…` with `text/calendar`.
  The resource contains one master and may include its timezone definitions
  and exceptions. `GET /webmail/api/calendar-timezone?zone=…` returns a
  VTIMEZONE definition from the binary's bundled IANA data.
- `GET /webmail/api/calendar-events/{id}` returns the event and its `ETag`.
  Pass that ETag unchanged in `If-Match` when updating with `PATCH` or removing
  with `DELETE`. A stale version returns `412` so the client can reload it.
  A patch may set `summary`, `description`, `location` or `time`. An empty
  description or location clears that field. Time changes on recurring events
  still use CalDAV. Other patches retain alarms, time zones, recurrence
  exceptions and imported properties.
- Use `GET /webmail/api/calendar-events/{id}?source=1` to retrieve the
  underlying iCalendar alongside its revision. `PUT` on the same item
  accepts `text/calendar` with one master and its exceptions, all with the
  original UID. It uses the same strong `If-Match` check and attachment scan.
  An occurrence edit writes a detached event with its original
  `RECURRENCE-ID`. Cancelling an occurrence marks that detached event
  `STATUS:CANCELLED`.
- `GET /webmail/api/calendar-reminders` returns the server time, the
  reminder window, candidate event resources, and dismissed reminder
  keys for the signed-in mailbox. `POST /webmail/api/calendar-reminders/dismiss`
  accepts `eventId`, `key`, and the due timestamp. Dismissal is idempotent.

## Calendar and contacts clients

Use the public DAV HTTPS address and your full mailbox address to connect a
CalDAV or CardDAV client. The profile at
`/email.mobileconfig?email=user%40example.com&services=dav` on that address lists
the host, public port, username and principal path for both services. If your
public DAV port differs from 443, set `CALDAV_PUBLIC_SSL_PORT` to the public
port so the profile points clients to the right place.

Vdirsyncer 0.19.2 was tested with both a `caldav` and a `carddav` storage. Set
each storage's `url` to the HTTPS origin from the profile and `username` to
the full mailbox address. With the certificate trusted, `vdirsyncer discover`
finds the collections and `vdirsyncer sync` transfers additions, edits and
deletions.

Open **Contacts** in webmail to browse your CardDAV address books, edit contact
addresses and notes, and maintain groups. **Email group** opens a draft with
the group’s available addresses for review. Edits appear in CardDAV clients at
their next sync. When a client edits the same card first, webmail asks you to
reload it before saving.

Choose **Account → Switch account** to save your current draft and return to
sign-in. Drafts and pending sends stay with the originating mailbox. Tabs that
still show the previous mailbox reload when they detect the new account.

Mail keeps up to `CALDAV_MAX_SYNC_HISTORY` recent changes in memory for
incremental DAV reports. The default is 10,000 changes across calendars and
address books. If history is pruned or the server restarts, clients with an
expired sync token can request the current collection with an empty token.

## Vacation replies

In **Account → Vacation reply**, enter a subject and plain-text message,
choose optional start and end times, and save with **Send vacation replies**
checked. Times are entered in your local timezone. Without a start time the
rule starts immediately. Without an end time it stays on until you turn it off.

Replies go to verified envelope senders whose messages name your mailbox in a
recipient header. Mail from mailing lists, system or automated senders,
forwarded copies, and messages filed in Junk or held for Sender Review do not
trigger a reply. Each qualifying sender can get one reply every seven days.
Hosted replies use the mailbox's daily sending allowance. A reply is released
after the original is filed. Changes apply to mail accepted after you save.
The reply uses your saved text and links to the original through its threading
headers. See [RFC 3834](https://www.rfc-editor.org/rfc/rfc3834.html) for the
automatic-response conventions.

## Password recovery

Each mailbox may have one recovery address outside itself. "Forgot password?"
on the sign-in page (`/forgot`) asks for the mailbox address and always answers
the same way, whether or not the mailbox exists or has a recovery address. When
it does, the server mails a reset link to the recovery address, from
`no-reply@<mailbox domain>` through the normal delivery path, so the message is
DKIM-signed with that domain's key. The link (`/reset#token=...`) works once,
expires after 30 minutes, and carries its token in the fragment so it never
reaches a server or gateway log. Setting the new password signs out every
session and tells the recovery address that the password was reset.

Limits: at most 3 links per mailbox per hour and one per minute (counted in the
database, so a restart does not reset them), plus a per-IP limit on requests and
on token attempts. A link is voided by a newer one, by any password change and
by any change of the recovery address. Only a token's SHA-256 is stored
(`mailbox_reset_tokens`).

Links point at `mail.<mailbox domain>` or the server hostname when the request
came in on one of those names, and at `SMTP_HOSTNAME` otherwise. The request's
Host header alone is never trusted, because a link built from it would carry the
token to whichever server the requester named.

Signed-in users see and change their recovery address under Account; saving
asks for the mailbox password again, and the previous address is notified.
Operators and deploy provisioning use the CLI:

```bash
mail user:local recovery pawel@example.com                               # show
mail user:local recovery pawel@example.com pawel@elsewhere.example       # set (policy managed)
mail user:local recovery pawel@example.com pawel@elsewhere.example --policy initial
mail user:local recovery pawel@example.com --clear
```

`users.recovery_source` records who set the address: `operator` (CLI) or
`user` (webmail). `--policy initial` sets it unless the owner has set or cleared
their own; `--policy managed` always sets it. The command prints one
`Recovery: updated|unchanged|kept|cleared` line and exits non-zero for an
unknown mailbox or an unusable address.

## Configuration

Declare `infrastructure.compute.managedServices.mail.webmail` in a ts-cloud
`CloudConfig`. The mail repository's `packages/cloud/webmail.config.ts` is a
consumer; it contains no separate certificate or deployment implementation.

```ts
webmail: {
  port: 8099,
  domain: 'mail.example.com',
  aliases: ['mail.other-example.com'],
  attachments: {
    maxFileBytes: 20 * 1024 * 1024,
    maxTotalBytes: 20 * 1024 * 1024,
    maxCount: 20,
  },
  undoSendSeconds: 10,
}
```

The executable reads `SMTP_WEBMAIL_ATTACHMENT_MAX_FILE`,
`SMTP_WEBMAIL_ATTACHMENT_MAX_TOTAL`, `SMTP_WEBMAIL_ATTACHMENT_MAX_COUNT` and
`SMTP_WEBMAIL_UNDO_SEND_SECONDS`. Byte limits accept 0–100 MiB, count 0–100 and
send delay 0–30 seconds. Effective attachment limits also respect mailbox limits
and the MIME expansion budget under `SMTP_MAX_MESSAGE_SIZE`; the UI displays the
actual effective limit. A user may choose a 0–30 second send delay in the composer.

## Import a mailbox over IMAP

Run `scripts/mail-import.py` with Python 3.12 or later and separate logins for
the old mailbox and the destination Mail account. Both connections use
certificate-verified IMAPS. Use mailbox-specific or app passwords. The command
prompts for them, or reads the source and destination passwords on separate
lines with `--password-stdin`. For a private CA use `--source-ca` or
`--destination-ca`.

```sh
python3 scripts/mail-import.py \
  --source-host imap.old.example --source-user person@old.example \
  --destination-host imap.new.example --destination-user person@new.example \
  --folder INBOX INBOX --folder "Projects/2024" "Projects 2024"
```

This previews the mapping and message counts. Omit the folder arguments to
list selectable source folders. Map each source folder to a distinct Mail
folder, including empty folders. Mail uses single-level folder names, so choose
a flat destination name for each nested source folder.

To copy, rerun the mapped command with `--apply --state /private/import/mail.sqlite`.
Use an operator-owned directory with restricted access. The private SQLite
checkpoint and its lock record progress for one account pair and mapping. Keep
them together and reuse the checkpoint when resuming. The importer reads the
source without changing read state. It keeps the message bytes, attachment
contents, received time, and Mail's five standard persistent flags. It also
preserves valid IMAP keywords with a destination that advertises
`XMAILDIR-KEYWORDS`. The JSON-line report lists imported and failed UIDs and
any unsupported flags. Each Mail folder supports up to 26 permanent keywords.
Mail refuses an APPEND that would exceed the folder's keyword capacity.

The checkpoint identifies each completed message by source folder, UIDVALIDITY,
and UID. Identical messages with different UIDs are each copied. The importer
stops a folder if either side changes UIDVALIDITY. For the final cutover, pause
source writes and rerun the same command to pick up new UIDs. Existing copies
keep their destination state when source flags, moves, or deletions change.

If a connection drops before the importer can record the APPEND result, it
holds that folder to avoid a duplicate. Inspect the destination and confirm
which UID belongs to the attempted copy. Rerun the same mapped command and
checkpoint with `--resolve "Source folder" SOURCE_UID DESTINATION_UID` in place
of `--apply`. Resolution verifies the destination generation, message bytes,
and received time before crediting the copy. Then rerun `--apply` to continue.
If you confirm the interrupted request has stopped and the copy was never
accepted, use `uncommitted` in place of `DESTINATION_UID`. The importer clears
the attempt only if the destination's UIDNEXT is still the one recorded before
the attempt.

## Portable mailbox export

Run the export as a local Mail operator with the same database paths and working
directory as the server. The command accepts the canonical mailbox username and
works while that mailbox's sign-in is disabled.

```sh
mail user:local export person@example.com /private/path/person.tar
tar -xf /private/path/person.tar -C /private/path/extracted
```

The operator chooses a new archive path. Mail writes the archive with mode
`0600` and publishes it after the export succeeds. The source paths default to
`mail/`, `smtp.db`, and `caldav.db`. Set `MAIL_ROOT`, `SMTP_DB_PATH`, and
`CALDAV_DB_PATH` to match the local data. Use a quiesced copy of the source
stores for a point-in-time export across mail and DAV.

- `Maildir/` contains Inbox and named folders in Maildir++ format. Message
  files retain their original MIME bytes and attachments. Standard flags travel
  in the filename and the archive carries file modification times to the second.
  In folders with IMAP keywords, `dovecot-keywords` maps lowercase filename
  flags to their names, with index 0 for `a` through index 25 for `z`.
  Dates outside the USTAR range, including pre-1970 dates, use PAX extended
  headers. GNU tar and bsdtar preserve these timestamps on extraction.
- `Calendars/` contains an iCalendar file for each owned calendar. Import them
  into a calendar client using its ICS import. The existing 16 MiB
  per-calendar export limit applies.
- `Contacts/` contains individual vCards grouped by address book. Import the
  cards into the corresponding address books on the destination.
- `manifest.json` maps source folder, calendar, and address-book names to their
  archive paths. Use the manifest when creating IMAP folders with their source
  names. The destination assigns its own message UIDs.

To move mail into another Mail instance, create each folder from the manifest
and upload its messages over IMAP. Pass the archived flags and file modification
time to APPEND to preserve the original received time. Translate lowercase
flags through the folder's `dovecot-keywords` file and pass the names as IMAP
keywords. Mail uses the current time
when a client omits it. Backdated imports still arrive at the end of the
destination folder. A Maildir importer such as Dovecot's can also read the
extracted folders directly. [Dovecot import documentation](https://doc.dovecot.org/2.3/admin_manual/importing_mailboxes/)

Use a server backup for same-service recovery of account configuration,
sharing, and private workflow state.

## Self-hosted team administration

Run these commands on the Mail host using the service database and a local
operator account that can write to it. The mailboxes must already exist.

```sh
mail team create studio "Studio" owner@example.com
mail team member studio colleague@example.com member
mail team grant studio owner@example.com colleague@example.com sender
mail team show studio
mail team revoke studio owner@example.com colleague@example.com sender
mail team member studio colleague@example.com remove
```

The API exposes roster and grant records through `GET /webmail/api/teams`
and `GET /webmail/api/teams/:id`. Team members see their own membership and
grants they participate in. Owners and admins see the full team. Local
operators enroll mailboxes. Owners manage existing roles with
`PUT /webmail/api/teams/:id/members` and `{mailbox, role}`. A null role removes
the membership. Admins may remove ordinary members.

`PUT /webmail/api/teams/:id/grants` accepts
`{source, grantee, scope, resource, allowed}`. Both mailboxes must be on the
team. A member can grant or revoke access to their own resources. Owners and
admins can also revoke grants within the team. The scopes `mailbox`, `sender`,
and `search` take an empty resource. The scopes `calendar`, `attachments`, and
`comments` take a specific resource ID. See the team workflow issues for
the rollout of these permissions to mail and calendar clients.

Assign a replacement before deleting, removing, or demoting the final owner.
A suspended mailbox retains its assigned role and cannot use its credentials.
The local operator can appoint an enabled replacement. Membership removal
revokes existing webmail sessions and deletes grants in both directions.
Role changes revoke the affected user's webmail sessions. The server records
membership and grant changes in `audit_log` in the same transaction.

### Calendar shares

In webmail Calendar, use **Manage calendars** to share an owned calendar
with a teammate. Choose the team, enter the teammate's full mailbox address,
and select **View events**, **Edit events**, or **Free/busy only**. Change or
revoke grants in the same panel. Team members can select incoming shares from
the calendar list. The browser checks access while the page is open and closes
shared event details when access changes.

The calendar owner can send `PUT /webmail/api/teams/:id/calendar-shares` with
`{calendarId, grantee, access}`. Use the ID from their calendar list and
the teammate's full mailbox address. The access values are `viewer`,
`editor`, and `free_busy`. Send `null` to revoke that share.

`GET /webmail/api/calendar-shares` lists the signed-in mailbox's incoming and
outgoing shares. Viewer and editor grants allow public event listings via
`GET /webmail/api/calendar-events` with the shared `calendarId`, and public
event details via `GET /webmail/api/calendar-events/{id}`. Resources with
private or confidential instances stay out of shared results.

Editors can create, update, and delete public events through the calendar event
API. Updates and deletions use the same `If-Match` requirement as owner edits.
Mail checks the grant again when it writes the event, after preparing and
scanning the request. Calendar exports require ownership. Free/busy grants
allow `GET /webmail/api/calendar-free-busy?calendarId=…&start=…&end=…`.
Owners, viewers, and editors can also query availability. Supply Unix seconds
for a half-open range of at most 366 days. The response contains only merged
busy periods as `{"busy":[{"start":…,"end":…}]}`. Private and confidential
events block time. Transparent and cancelled events leave it free.

The server resolves calendar dates and named time zones and applies supported
sub-daily, daily, weekly, monthly, and yearly rules, explicit dates and
exclusions, and individual and `RANGE=THISANDFUTURE` overrides.
A `422 availability_incomplete` response means the server could not calculate
all busy times, for example for rules that use `BYWEEKNO`. A
`413 availability_limit` response means the calculation exceeded a limit.
Treat either response as unknown availability.

CalDAV clients can send a `CALDAV:free-busy-query` report to the URL of an
individual calendar from the owner's CalDAV collection listing. The URL uses
the owner's username and the calendar's encoded path name. The report uses the
same team grants as webmail. Pass UTC iCalendar dates and `Depth: 1` to
include the calendar's events.

```xml
<C:free-busy-query xmlns:C="urn:ietf:params:xml:ns:caldav">
  <C:time-range start="20261208T000000Z" end="20261209T000000Z"/>
</C:free-busy-query>
```

The report returns one `VFREEBUSY` component. It merges overlapping or
adjacent intervals of the same type and preserves tentative and unavailable
periods. `Depth: 0` returns an empty component after checking access to the
collection. An unauthorized request returns 404. The free/busy privilege gives
access to this report only.

Viewers and editors can open the shared collection at that same URL.
`PROPFIND` with `Depth: 1` lists public event URLs and ETags, and
`calendar-query` and `calendar-multiget` return public event resources.
Event URLs also support `GET` and `HEAD`. The collection's
`DAV:current-user-privilege-set` describes whether the requester can edit.
The teammate's CalDAV principal advertises a personal home and a shared
home. The shared home lists only calendars the teammate can read. Each has a
stable URL under `/shared-calendars/<teammate>/` and uses the same grants as the
owner's direct URL. For clients that discover only the first calendar home,
enter the shared home URL as an additional CalDAV connection with the
teammate's credentials.

Shared calendars support `DAV:sync-collection` with their own opaque
checkpoints. An empty sync token lists the current public events. Later
reports return public adds and edits and mark formerly public events as
removed when they are deleted or made private. Checkpoints are scoped to the
authenticated teammate, grant, and collection URL type. A revoked grant
denies access immediately. If a grant changes, the daemon restarts, or a
checkpoint ages out of the bounded cache, a 403 with
`DAV:valid-sync-token` tells the client to start again with an empty token.
If the collection exceeds the checkpoint budget, the sync report returns
507. Clients can refresh the public listing and compare event ETags.

In both owned and shared collections, a `VEVENT` time range in a
`calendar-query` report matches any overlapping occurrence. Results include
the original resource. The range includes its start and excludes its end.
Date filters use the same recurrence evaluation as availability. A report can
supply a `VTIMEZONE` for floating times. Transparent events still match.
An incomplete calculation returns 422. Exceeding the recurrence work limit
returns 507.

Editors can `PUT` and `DELETE` public events in the existing shared
collection. Use `If-None-Match: *` to create and `If-Match` with the latest
ETag to update or delete. Private and confidential resources return 404,
including recurring resources with a private or confidential occurrence.
An editor's attempt to save a non-public replacement returns 422. The server
checks the current grant on each request and again after scanning a write.

### Shared inboxes

Create a mailbox for the shared address and enroll that account and its
teammates in the same team. For example, the operator can grant
`mail team grant studio studio@example.com alex@example.com mailbox`. Direct
mail for the address lands in its own Inbox. Forwarding aliases redirect to
other mailboxes, and catch-all routing handles otherwise-unmatched addresses.
The mailbox grant shares work on a mailbox. A teammate still signs in to their
personal account. Grant `sender` separately to allow sending from the address.

Open **Shared inboxes** in webmail to read incoming messages, assign a teammate,
resolve or reopen work, and see who changed it. The view covers the Inbox,
while the source mailbox keeps its own folders, sessions, and personal
metadata. To share attachment downloads, grant `attachments` for the specific
message reference in that team.

Use **Reply** on an open shared message to prepare a private draft with the
shared From address and the original reply headers. It requires Inbox access
and the sender grant in the same team, or ownership of the shared mailbox.
When a teammate is assigned, they handle the reply. One Outbox send can
reserve the original message at a time, including scheduled sends. The other
teammate’s draft stays available if their send conflicts. Removing a team grant
cancels that teammate’s pending shared reply and restores its draft.
Cancellation and definite failure release the reservation. A delivered reply or uncertain
delivery stays marked on the original message to prevent a repeat.

- `GET /webmail/api/shared-inboxes` lists accessible team and mailbox pairs.
- `GET /webmail/api/shared-inboxes/:team/:id?page=1` returns one Inbox page.
- `GET /webmail/api/shared-inboxes/:team/:id/messages/:reference` returns the
  shared message and workflow. Its attachment links require both the mailbox
  grant and the per-message attachment grant for teammates.
- `PUT .../messages/:reference/workflow` accepts `action`, `revision`, and
  `messageRevision`. Use `assign` with an `assignee` ID or use `unassign`,
  `resolve`, or `reopen`. A competing edit returns 409. Revoking the mailbox
  grant clears that teammate’s assignments and prevents further access.
- `POST .../messages/:reference/reply` accepts the current `messageRevision`
  and a client-generated `draftId` to prepare the linked draft. Submit it
  using the Outbox send ID. The server checks the reservation, team access,
  assignment, and shared address again at delivery admission.

## API contracts

All mutations require a session and same-origin request. Clients include
`X-Webmail-Account` with the URL-encoded full account address; attachment links
include the equivalent `account` query parameter. A changed account returns 409
before a request may affect another mailbox. Disabling or deleting an account
revokes existing webmail sessions.

- `GET /webmail/api/config` returns effective limits and preferences.
- The [calendar API](#calendar-api) uses the same store as CalDAV. Recurring
  event summaries include their rules as candidates for occurrence expansion.
  The endpoints report 503 when DAV is disabled and 404 for a missing or
  foreign calendar.
- `POST /webmail/api/drafts` accepts `draftId`, `draftRevision`, `saveToken` and
  composition fields, including recipient labels, unfinished inputs and staged
  attachment IDs. Repeating the identical save token returns its acknowledgement;
  a stale revision returns 409. `GET /webmail/api/drafts/:id` restores metadata.
- `GET /webmail/api/compose-library` returns the account's plain-text snippets,
  signatures and optional `defaultSignatureId`. `PUT` replaces the library using
  the current `revision`. A stale revision returns 409. Webmail inserts the
  default signature into new compositions, including replies and forwards,
  and keeps the resulting text in saved drafts and scheduled messages.
- `GET /webmail/api/sender-identities` lists active delegated addresses with
  their `id` values. Compose and drafts accept an optional `senderId`. The server
  checks the grant when queuing and again in the delivery admission
  transaction. The signed-in mailbox owns the draft, Outbox, Sent copy, and
  recipient usage. When a grant is revoked before admission, the Outbox marks
  the send failed and preserves its draft so the sender can choose a different
  address. Recovery uses the From address recorded at admission.
- `POST /webmail/api/uploads?filename=...&contentType=...&uploadId=...` stages
  raw bytes. Repeating an ID and identical content succeeds; different content
  conflicts. `DELETE /webmail/api/uploads/:id` removes an unused owned upload.
- `POST /webmail/api/bulk` validates up to 100 folder/UID references before
  mutation and returns individual results plus an optional Undo receipt.
  Its `junk` and `not_junk` actions require a stable message reference and
  current revision for each item.
  `POST /webmail/api/undo/:id` restores an unchanged receipt once, idempotently.
- `POST /webmail/api/compose` with a stable `sendId` queues a validated message.
  Set `delaySeconds` for an Undo Send hold or `scheduleAt` to an integer Unix
  timestamp within the next 365 days. The Outbox keeps the scheduled message
  across server restarts. Replaying the same ID cannot dispatch twice.
  `GET /webmail/api/outbox` exposes results and `DELETE /webmail/api/outbox/:id`
  cancels a pending send before its deadline. In webmail, **Edit scheduled send**
  pauses the original schedule and opens the draft with its send time selected.
  Set the next schedule explicitly after editing. A reviewed Unknown record
  may be resolved explicitly. Use `GET /webmail/api/outbox?view=upcoming`
  for bounded summaries ordered by the earliest send time, or use
  `view=review` and `view=history` for their respective lists. Pass the returned
  `nextCursor` as `after` for the next page. Expired or foreign cursors return
  `outbox_cursor_expired`. Use `view=overview` for account totals alone and
  `track=<sendId>` to include the current status of a send on any page. The
  request without a view continues to return the legacy array.
- `POST /webmail/auth/forgot` `{address}` always returns `{ok:true}` (429 when
  the IP is over its limit). `POST /webmail/auth/reset/verify` `{token}` returns
  `{account}` without spending the token; `POST /webmail/auth/reset`
  `{token,password}` spends it and sets the password. A dead token is 400
  `invalid_token`. These three need no session but must be same-origin.
- `GET /webmail/auth/recovery` returns `{recovery, setBy}`;
  `PUT /webmail/auth/recovery` `{currentPassword, recovery}` changes it, and an
  empty `recovery` removes it.
- `GET /webmail/api/forwarding` returns `{address, pendingAddress, expiresAt,
  revision}`. `POST` accepts the current `revision` and an `action` of
  `request`, `confirm`, `cancel`, or `disable`. A request needs `address`
  and `currentPassword`, confirmation needs `code`, and disabling needs
  `currentPassword`. A stale revision returns 412. See
  [mailbox forwarding](docs/FORWARDING.md#mailbox-forwarding).
- `GET /webmail/api/vacation` returns `{enabled, subject, body, startsAt,
  endsAt, revision}`. Send those fields in `PUT` to change the rule. The times
  are optional Unix seconds, with an inclusive start and an exclusive end.
  A stale revision returns 412.
- Existing immediate-compose and message endpoints remain compatible with the
  native SDK and older clients. New clients use the durable draft and queue APIs.

### Hosted compose storage

Hosted mailboxes have separate budgets for temporary SQLite data. Maildir
messages, including any saved Draft or Sent copy, still count toward the
mailbox byte quota. Recipient allowances are charged when mail is dispatched.

| SQLite data | Byte budget per hosted mailbox | Record limit |
| --- | --- | --- |
| Staged uploads | Twice the effective attachment total, with a 1 MiB minimum | 128 |
| Draft metadata | Twice the server message-size limit, with a 1 MiB minimum | 200 |
| Outbox | Twice the server message-size limit, with a 1 MiB minimum | 1,024 |

The record budgets use serialized UTF-8 bytes. Pending, sending, and unknown
Outbox entries reserve 64 KiB each for the eventual delivery result. New data
that would exceed a budget returns HTTP 413. A draft replacement can reuse its
existing space. Older rows count toward the limits and are retained under the
same expiration rules. API clients can read or retry the same acknowledged
draft or send while the applicable budget is full.

Unused uploads can be deleted immediately. Unreferenced uploads expire 24
hours after staging. A draft or retryable Outbox item keeps its referenced
uploads available. Permanently deleting a draft releases its metadata budget.
Successful sends keep a small receipt and request digest for seven days, so a
repeat of the same send ID can still recover its result after attachments are
released. Failed, partial, cancelled, and reviewed entries remain available
for seven days. An interrupted send keeps its complete payload and attachments
until the mailbox owner reviews it. Account removal cascades to these SQLite
records. SQLite reuses freed pages for future writes.

## Validation and release

Run `bun test`, the strict TypeScript check for webmail composables, Pickier, and
`zig build test` with the repository's pinned Zig toolchain. `bun run build` in
`packages/webmail` compiles the embedded stx pages. The Zig build also does this.
Live API suites in `packages/webmail/{e2e,ux-e2e}.test.ts` run with
`MAIL_WEBMAIL_E2E_URL`, `MAIL_WEBMAIL_E2E_USER` and `MAIL_WEBMAIL_E2E_PASSWORD`.
Use a disposable owned mailbox: these tests send messages and exercise deletion.
With CalDAV enabled, set `MAIL_WEBMAIL_E2E_CALDAV_URL` to its origin to also
verify that a CalDAV write appears in the webmail calendar.

### Upgrading persisted DAV data

The new DAV store records collection ownership using the mailbox's database ID.
Older DAV databases may have collections whose numeric owner has no durable
mapping. The upgrade keeps those rows and reserves their IDs. Those collections
stay unavailable until an operator verifies and assigns their owners.

Back up the mail and DAV databases together. Verify each collection using a
trusted historical mapping or an owner-provided export. A legacy number alone
cannot prove ownership. Supply only verified assignments in a JSON file.

```json
[
  { "kind": "calendar", "id": 12, "mailbox": "owner@example.test" },
  { "kind": "address_book", "id": 3, "mailbox": "owner@example.test" }
]
```

During an offline maintenance window, with the mail daemon stopped, validate
the assignment file before applying it:

```bash
python3 scripts/migrate-dav-ownership.py --mail-db ./smtp.db --dav-db ./caldav.db --assignments ./assignments.json
python3 scripts/migrate-dav-ownership.py --mail-db ./smtp.db --dav-db ./caldav.db --assignments ./assignments.json --apply
```

The second command applies the complete file in one DAV transaction. An
existing assignment to the same mailbox is safe to repeat. A different
registered owner aborts the operation. Verify the assigned collections on a
restored copy before making the change in production.
Browser acceptance covers draft recovery, recipient validation, bulk Undo,
conversation expansion, filtered search, large attachment byte integrity and
Undo Send, including a mobile viewport.

Commit source fixes, push main, run `bun run release:patch`, then pull and consume
published dependencies. Deploy the released executable through the native
workflow and verify the live HTTPS UI with real mailbox credentials.

## Historical design notes

The following original phased plan records early implementation decisions. The
current behavior and contracts above supersede its status and remaining-work notes.

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

### Phase 3 — Frontend: app shell & auth UI  ·  ✅ DONE
**Tasks**
- [x] App shell with the 3-pane layout (folder sidebar │ list │ reading pane),
      responsive collapse for mobile (single-pane on ≤860px).
- [x] Login + logout pages wired to Phase 1 endpoints; session-expiry handling
      (any 401 → redirect to /login).
- [x] Loading / empty / error states.
- [~] Client-side routing — kept simple: `/login` + `/` full pages; in-app view
      switching (list ↔ reading) is state-driven. Compose view is Phase 6.
- [~] API access — inline `fetch` per the standalone-page approach (the Phase 0
      `useApi.ts` stub was removed; see "Notes" below).

**Acceptance** ✅ verified in headless Chrome end-to-end: log in via the form →
land on inbox → folders + message list render from the API → open a message
(headers + sandboxed HTML iframe / plain-text) → sign out returns to /login.
Bonus already done (overlaps Phase 4): real folder tree with unread counts,
paginated-ready list, sandboxed HTML rendering.

**Notes / deviations (see memory `stx-client-side-gotchas`):**
- Pages are **standalone HTML + vanilla `<script>`** (the `devtools/app.stx`
  approach), **not** stx `@extends` layouts or Alpine directives — those get
  stripped under a layout without their reactive runtime. The Phase 0
  `layouts/`, `partials/`, `functions/useApi.ts` scaffold was removed as dead.
- Login field is `type="text"` (backend accepts bare username or full address;
  `type="email"` silently blocked username-only login via HTML5 validation).
- HTML email renders in an empty-`sandbox` iframe via `srcdoc` (no scripts, no
  same-origin) — the Phase 8 XSS-isolation approach, brought forward.

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

### Phase 5 — Flags & message actions (persisted)  ·  ✅ DONE
**Tasks**
- [x] Backend write ops (`webmail_maildir.zig`): set flags (read/unread,
      flag/star) via `:2,FLAGS` rename; delete (→ Trash, or purge in Trash);
      move between folders. `PUT`/`DELETE /webmail/api/messages/:uid` with
      same-origin (CSRF) + session enforced.
- [x] **IMAP consistency:** UIDs keyed on the Maildir **base name**, so flag
      renames keep the UID stable and webmail/IMAP/ActiveSync agree. Fixed two
      pre-existing UID bugs in the shared `database.zig` path (full-name keying;
      `assignUid` duplicate-UID on `INSERT OR IGNORE`). Covered by
      `uid_consistency_test.zig`.
- [x] Frontend: reading-pane toolbar (flag / mark-unread / delete), flagged ★ in
      the list, optimistic UI + rollback, auto-mark-read on open (race-guarded).
- [x] Verify round-trip: webmail action → correct `:2,FLAGS` on disk + stable
      base-name UID in `imap_uids` (what IMAP reads). Confirmed via curl + disk
      inspection + headless-browser drive.
- [~] Bulk/multi-select actions: deferred to a later polish pass.

**Acceptance** ✅ mark-read writes `:2,S` keeping the UID; move relocates the
file + returns the dest UID; delete moves to Trash; cross-origin mutation → 403.

**Hardening (adversarial review, 11 findings fixed):** error-propagating
`unlinkPath` (no phantom-success deletes / no move duplication), dest-UID-before-
move ordering, `setFlags` retry→409 on concurrent rename, symlink skip in
`listEmlFiles` (planted-symlink path-escape), `jsonBoolField` terminator check,
frontend rollback + auto-read race guard.

> **Known unfixed (separate subsystem):** SMTP delivery can overwrite a message
> on same-millisecond delivery (bare-timestamp Maildir name + `O_TRUNC`). See
> memory `smtp-maildir-filename-collision`. Not a webmail bug; fix in the
> delivery path.

---

### Phase 6 — Compose & send  ·  ✅ DONE
**Tasks**
- [x] Composer UI: to/cc/bcc (validated), subject, plain body, reply /
      reply-all / forward (quote + `Re:`/`Fwd:` + `In-Reply-To`/`References`).
- [x] Backend: `POST /webmail/api/compose` builds a correct RFC 5322 MIME
      message (`webmail_compose.zig`) and sends via the **existing**
      `outbound.deliverToRemote` (SES/direct) — not a new client.
- [x] **Save to Sent** (writeMaildir to the sender's `Sent`).
- [x] **DKIM** is automatic: `deliverToRemote` signs via the process-wide signer,
      so webmail mail is signed exactly like SMTP submission. Local recipients
      land in their INBOX; remote go out.
- [x] Multi-agent adversarial review + 11 fixes (see below).
- [~] Rich (HTML) compose, attachment **upload** UI, and **Drafts** persistence:
      deferred to a polish pass. (The MIME builder already supports html +
      base64 attachments; only the upload UI/draft endpoints remain.)

**Acceptance** ✅ verified in headless browser + on disk: compose → recipient
INBOX with correct headers + Sent copy; reply threads via In-Reply-To/References;
multi-line + non-ASCII bodies correct; header-injection recipient → 400.

**Security hardening (adversarial review):** fixed a **CRITICAL path traversal**
(crafted local-part escaping `mail/{user}/`), predictable/unchecked MIME
boundaries, silent partial-delivery loss (now reported), Maildir overwrite
(O_EXCL + retry), Bcc validation, and 8bit→base64 for non-ASCII. Kept
`isLocalDomain`'s parent-domain acceptance to stay identical to the SMTP path.

**Risks:** Outbound signing matches production by reusing the same path. Real
external deliverability (SPF/DKIM/DMARC at the receiver) still warrants a live
send test against an external mailbox before launch.

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

### Phase 9 — Production serving & deployment  ·  🟡 BUILT & LOCALLY VERIFIED (prod deploy deferred)
Decision: **Option A — embed the built SPA in the Zig binary**, with the webmail
server terminating **TLS directly** (like IMAPS/CalDAV). Single binary, no extra
moving parts. Verified locally over HTTPS; the live prod deploy is a separate,
explicit step (see runbook below).

**Serving model — done**
- [x] `packages/webmail/build.ts` renders the two standalone pages + CSS to
      `packages/zig/src/api/webmail_dist/` (gitignored). `zig build` runs it
      automatically (build.zig system step), so embedded assets are always fresh.
- [x] `webmail_http.zig` `@embedFile`s `index.html`/`login.html`/`styles.css` and
      serves `GET /`, `/login`, `/styles.css` (with `nosniff`/`DENY`/cache
      headers). Pages call `/webmail/*` same-origin — no proxy in prod.
- [x] Direct TLS (`webmail_tls.zig`): nonblock handshake + record I/O via a
      `Stream` abstraction (plain or TLS), mirroring caldav.zig. Reuses the
      Let's Encrypt `CertKeyPair` loader. Config: `enable_tls` +
      `tls_cert_path`/`tls_key_path`; wired in main.zig (binds `0.0.0.0` and sets
      `Secure` cookies only when TLS is on).
- [x] Verified locally end-to-end over HTTPS (self-signed): login → inbox (6
      folders) → all served from the single binary on `:8443`.

**Fix found during this phase:** an accepted connection inherited the listener's
non-blocking mode on this platform, so the TLS handshake read hit `WouldBlock`
and failed. Added `socket.Connection.setBlocking()`, called after accept. (Would
have broken the prod deploy — caught locally.)

**Deferred to the explicit prod-deploy step (runbook):**
- [ ] Open the webmail port (default **8443**) in the EC2 security group
      (`packages/cloud/cloud.config.ts`).
- [ ] Set env on the box (`/etc/mail/mail.env`): `SMTP_ENABLE_WEBMAIL=true`,
      `SMTP_WEBMAIL_PORT=8443` (TLS reuses the existing `SMTP_ENABLE_TLS=true` +
      `SMTP_TLS_CERT`/`SMTP_TLS_KEY` Let's Encrypt paths).
- [ ] Deploy via SSM (CLAUDE.md flow): `cd packages/zig && zig build
      -Doptimize=ReleaseFast -Dtarget=x86_64-linux` (auto-builds the frontend +
      embeds it) → `aws s3 cp zig-out/bin/mail s3://…/deploy/mail-server-new` →
      SSM swap binary + `systemctl restart mail`.
- [ ] Smoke test: `curl https://mail.stacksjs.com:8443/login` → 200; log in with
      a real mailbox.
- [ ] (Optional) Decide final URL: `:8443` vs. moving CalDAV off 443 to free it,
      vs. a `webmail.` subdomain. Add webmail health to the Discord monitor.

**Acceptance (local):** ✅ webmail fully served from the single binary over HTTPS,
login→inbox verified in a headless browser. **Prod acceptance** remains the
deferred deploy above.

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

Message listings and details include the mailbox-scoped `reference` and `revision`.
`GET /webmail/api/messages/ref/:reference` follows the message across folder moves and returns its current `folder`, `uid`, and strong `ETag`. A flag change keeps the reference and changes the revision. A copy gets its own reference. An expunged message or a reference from another account returns `404`.

`PUT` and `DELETE` on the reference URL require the last `ETag` in `If-Match`.
Missing preconditions return `428` and stale revisions return `412`. For `POST /webmail/api/bulk`, pass `reference` and `revision` alongside `uid` and `folder` for each selected message. A stale revision rejects the selection before any action runs. Existing UID routes remain available for older clients.

For personal mailbox attachments, pass `reference`, `content_revision`, and the
zero-based `index` to `GET /webmail/api/attachment`. The content revision comes
from the message or attachment library response and stays valid through flag
changes. Changed MIME bytes cause `412`. The older `revision` parameter still
accepts the full message revision, including flags.

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

## Delivery health and incident visibility

The inbox links to `/status` and shows a banner when monitoring is degraded or
unavailable. Signed-in mailbox users can see protocol checks and a persistent
incident history. No message content, recipient addresses, sender IPs or webhook
credentials are included. Reports older than three minutes are shown as unknown,
including when polling stops while the page remains open.

On the mail host, install the monitor with:

```sh
sh scripts/setup-mail-health.sh scripts/mail-health.py
systemctl start mail-health.service
systemctl status mail-health.timer mail-health.service
```

The timer checks commands after verified TLS on SMTP, submission, SMTPS and IMAPS,
including independently encrypted TLS 1.3 records with zero padding. It also watches
the delivery journal, disk capacity and write/fsync access as the daemon user. A
systemd drop-in prevents an older tenant deploy from replacing these checks with
listener-only checks. Deployments verify a candidate in an isolated mailbox first,
and roll back activation when real protocol checks fail.

`DISCORD_WEBHOOK_URL` in `/etc/mail/mail.env` sends incident and recovery alerts
through HTTPS, independent of SMTP. Failed notifications persist in a root-only
retry queue. The daemon can read only the sanitized status artifact at
`/var/lib/mail-health/public/status.json`; private state is under
`/var/lib/mail-health/private/`. A corrupt private state file fails the monitor
instead of silently discarding pending notifications. Investigate and preserve it
before repairing it. Do not erase it as routine cleanup.

The public `/healthz` endpoint returns only healthy/unavailable, with HTTP 503 for
failed or stale monitoring. The five-minute Public Mail Health workflow checks
this endpoint and the public mail protocols from outside the host. Configure the
repository secret `MAIL_HEALTH_WEBHOOK` with the administrator's Discord webhook.
Its first failure opens a GitHub incident and alerts the administrator; repeated
failures reuse that incident. Recovery alerts and closes the incident. Notification
failures leave the incident open for retry. GitHub schedules can be delayed, so
this is a separate backstop to the host's minute timer.

For an immediate external diagnosis:

```sh
python3 scripts/mail-health.py --host mail.example.com --connect-host SERVER_IP
python3 scripts/test-mail-health-watch.py
python3 scripts/test-mail-tls.py packages/zig/zig-out/bin/mail
```

The last command uses a temporary server and mailbox, including a forced DNSBL
listing and a forced storage sync failure on Linux. SMTP must return 451 without
publishing a message when the sync fails. Successful local SMTP delivery writes
to a hidden temporary file, flushes it, publishes it without overwriting an
existing message and syncs the directory before acknowledging acceptance.

The AWS receipt incident exposed two independent failures: TLS 1.3 padding was
mistaken for the inner content type, and a pre-greeting DNSBL disconnect ignored
the configured score-only policy. TLS padding is decoded according to
[RFC 8446 section 5.2](https://www.rfc-editor.org/rfc/rfc8446#section-5.2).
DNSBL rejection is now an explicit opt-in SMTP reply at RCPT. A TLS handshake or
an open port alone is insufficient evidence that a server can receive mail.

### Read-only service monitoring

`GET /health/report` exposes the sanitized service-health envelope to monitoring
systems. Send `oh-dear-health-check-secret` with the 64-character credential in
`/var/lib/mail-health/public/read-token`. The installer generates it once and
preserves it across deploys, readable only by root and the mail daemon group.
An absent or incorrect credential returns 401. This credential grants no mailbox
access. Responses disable caching and return 503 for unavailable, stale or
unhealthy monitoring evidence. The public `/healthz` remains a summary only.

StatusHQ can poll this endpoint as a health monitor. Configure a 180-second
maximum report age and require the complete expected check inventory. Route
incidents and recoveries through an independent alert channel as well as any
email notifications. Public health, certificate and TCP monitors should run
outside the mail host to detect host, routing and listener outages independently.

## Private hosted provisioning

Set `SMTP_PROVISIONING_PORT`, `SMTP_PROVISIONING_DOMAIN`, and
`SMTP_PROVISIONING_TOKEN` to start the version 1 provisioning listener. The
token is a 32-byte random secret encoded as 64 hex characters. The listener
binds exclusively to `127.0.0.1` and exposes no browser routes. The ordinary
webmail listener exposes no provisioning routes. Keep the app on the same
host or use a private authenticated tunnel when it runs on another host.

The provisionable domain must already be a local SMTP domain. Hosting
configuration remains the source of truth for domain routing and DNS.
Provisioning is unavailable in catch-all mode. Each request uses the
provisioning bearer token. Requests with a browser Origin or Cookie are
rejected.

- `GET /provisioning/v1/status` returns `version` and the allowed `domain`.
- `GET /provisioning/v1/domain?name=...` confirms the configured provisionable
  domain.
- `GET /provisioning/v1/mailbox?mailbox=...&actor=...` observes a managed
  mailbox's current revision, storage quota, daily recipient allowance and enabled state.
- `POST /provisioning/v1/mailbox` accepts `mailbox`, `actor`, `operation_id`,
  `revision`, `quota_bytes`, `send_recipients_per_day`, and `enabled`.
  Set both limits to positive values for free signup. Omitted or zero
  `send_recipients_per_day` preserves compatibility with older clients
  that did not set an allowance. Revision 1 also accepts
  `initial_password` and `initial_recovery`. The same latest operation can be
  repeated. Creating the mailbox and recording ownership happen in one
  SQLite transaction. The initial password is used only on the first
  successful creation. Changes advance by one revision. An old request or an
  operation ID reused for another change conflicts. The listener never takes
  ownership of an existing unmanaged mailbox.

The actor is a stable opaque ID for the app's verified signup, and an actor
can own one mailbox. Suspension disables mailbox authentication and revokes
webmail sessions and password reset tokens.

### Limits across mail clients

- Storage counts stored message bytes in the mailbox's Maildir, including
  Inbox, Junk, Drafts, Sent, Trash and custom folders. Permanent deletion frees
  storage. Moving to Trash keeps the bytes allocated. Replacing a draft
  requires space only for its growth. Webmail's existing attachment staging
  and Outbox records are held separately from Maildir.
- SMTP DATA and BDAT return `452 4.2.2` if a local destination lacks space
  and `550 5.2.1` if it is disabled. The server checks all local recipients
  before publishing a transaction. Webmail reports full storage on draft
  saves and local delivery. If mail was delivered but the Sent copy would
  exceed the quota, Outbox reports delivery and the missing copy.
- IMAP APPEND, COPY and UID COPY use the same Maildir quota and return
  tagged `NO [OVERQUOTA]` when the operation exceeds it. A multi-message COPY
  checks its total size before creating any destination copies.
- One allowance covers distinct envelope recipients per submission, including
  local recipients and To, Cc and Bcc in webmail, EWS and ActiveSync. It resets
  at midnight UTC.
  SMTP returns `452 4.7.0` at exhaustion. Immediate webmail sends return
  `429`. Outbox checks the allowance at dispatch and reports failures there.
  Webmail reserves the attempted recipients before delivery, so failed or
  partial delivery can still use the allowance. SMTP delivery retries use
  their original reservation. A provisioning revision does not reset usage.
- EWS CreateItem and SendItem return `ErrorSubmissionQuotaExceeded` at the
  sending limit. Saving a draft uses mailbox storage without spending the
  sending allowance. When a caller requests a Sent copy, EWS checks its
  storage before delivery and returns `ErrorQuotaExceeded` if the copy would
  exceed the limit. EWS SendOnly works when the sender's storage is full.
  See the [EWS response codes](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxwscdata/53734587-8b80-4cd8-b0ea-92da6b960d9e).
- EWS scans file attachment bytes and the assembled message before CreateItem
  or CreateAttachment writes it. SendItem scans the stored MIME again before
  delivery or filing Sent. Malware, excessive scan size, and a fail-closed
  scanner outage return `ErrorVirusDetected`, `ErrorMessageSizeExceeded`, and
  `ErrorServerBusy` respectively, before charging the sending allowance.
  GetItem lists file attachment IDs and GetAttachment returns their bytes.
  CreateAttachment and DeleteAttachment update saved mail drafts and advance
  the webmail draft revision when one exists. Edits to drafts queued in Outbox
  return `ErrorIrresolvableConflict` while the queued copy is active.
- ActiveSync SendMail, SmartReply, and SmartForward use the authenticated
  mailbox for From and the quota.
  It checks a requested Sent copy before delivery and leaves Bcc out of
  delivered MIME. WBXML responses use status `113` for mailbox storage,
  `115` for the sending allowance, and `118` for a repeated accepted
  ClientId. Mail remembers an accepted WBXML ClientId for seven days per
  account and device. This prevents duplicate sends and charges after a lost response.
  Older raw MIME clients receive HTTP `507` for storage and `503` for
  a depleted allowance. See the [ActiveSync status codes](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-ascmd/95cb9d7c-d33d-4b94-9366-d59911c7a060).
  SmartReply and SmartForward resolve the original from that account's Sync
  item ID or Search `LongId`. The server adds the original display body for
  replies and retains its MIME attachments for forwards. WBXML `ReplaceMime`
  uses the complete client content with shared sender and Bcc handling. The
  quota check uses the final stored message after adding any original content.
  A malformed recurrence `InstanceId` returns `104`. A valid occurrence
  returns `147` until calendar scheduling MIME is available in [#47](https://github.com/mail-os/mail/issues/47).
  See [SmartReply](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-ascmd/419e4fc2-d0cb-419e-a94d-df4b8da0c98f)
  and [SmartForward](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-ascmd/7dd31ff2-7b47-4968-a6ed-79ebbd3cceb8).
- ActiveSync mailbox Search matches keywords in decoded mail headers and
  plain-text bodies in the synchronized mail folders. It supports a folder
  filter, date bounds and up to 50 results per page. Searches that would
  examine more than 10,000 messages or read more than 256 MiB return a
  Search timeout so clients can narrow the query. A Search `LongId` remains
  usable across flag changes and restarts in the same account. After moving
  an item to a different folder, search again for its new ID. See the
  [ActiveSync Search command](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-ascmd/8211179b-14f3-44ab-9de6-b69ca2a48c4e).
- ActiveSync Sync, GetItemEstimate, and Ping reconcile each mailbox, device,
  and collection independently. Mail state uses message IDs and read flags.
  Calendar and Contacts state uses resource revisions, so pruning the DAV
  change journal does not discard unseen changes. The device gets a new
  opaque Sync key when it initializes a collection or acknowledges changes.
  Each mailbox and device also keeps its own Ping heartbeat and watched folders.
  The first Ping supplies both settings, and later requests can reuse them.
  Clients upgrading from the older shared state receive an invalid-key
  response and must restart that collection with key `0`. The old tables are
  retained for rollback. Deleting a mailbox removes its new snapshots.
  See the [ActiveSync Sync key reference](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-ascmd/bb649593-c793-415e-912e-e7da9b7319bf).
- The account is checked again when an SMTP submission is accepted or
  Outbox dispatches. Persisted SMTP retries for suspended accounts are held
  until re-enabled. SMTP workers and Outbox jobs that already began dispatch
  can finish. Limits are enforced within a single Mail daemon writing the
  mailbox store. See [#61](https://github.com/mail-os/mail/issues/61) for
  the broader hosted rollout.

Run the boundary check against the compiled Mail binary.

```sh
python3 scripts/test-hosted-limits.py packages/zig/zig-out/bin/mail
```

Add `--staging` to use the staging profile in an isolated fixture with a
temporary TLS certificate. This exercises SMTP and IMAP over STARTTLS and
implicit TLS, and webmail, EWS, and ActiveSync over HTTPS.
