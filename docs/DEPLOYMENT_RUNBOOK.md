# Mail Server Deployment Runbook

**Version:** v0.28.0
**Date:** 2025-10-24

## Overview

This runbook provides step-by-step procedures for deploying, upgrading, and maintaining the Mail Server in production environments.

## Native Mail staging on AWS

Use a public Route 53 zone dedicated to the staging mailbox domain. For example, `mail.staging.example.com` is the server hostname and `staging.example.com` is the zone and mailbox domain. Delegate the zone from its authoritative parent and verify that a public NS lookup returns the Route 53 nameservers before creating the stack. The stack manages only the staging hostname's A record. Staging supports delivery between its own mailboxes. Its security group limits internet egress to HTTP and HTTPS.

Build the chosen Linux x86-64 revision with `zig build -Dtarget=x86_64-linux-gnu -Doptimize=ReleaseFast` in `packages/zig` after installing the repository dependencies. Publish a gzip tar archive under `staging/` in the test artifact bucket. Use the built executable as `mail-server` and include `scripts/mail-health.py`, `scripts/mail-health-watch.py`, `scripts/mail-sync-health.py`, and `scripts/setup-mail-health.sh` from the same revision at the archive root. Record the revision and SHA-256 of the archive.

Create `/mail-server/staging/provisioning-token` as an SSM SecureString in the target region with a 32-byte hex-encoded token. `/mail-server/staging/discord-webhook-url` is an optional SecureString for a staging alert receiver. The instance role can read those parameters and the selected artifact.

If Discord rate limits the watchdog, pending alerts stay in the private
outbox until the `Retry-After` or `retry_after` deadline. When the response
omits a usable delay, the watchdog waits one minute. It continues publishing health
results during the wait. The `Admin alert transport` entry in its status
file exposes the pending count and a `retry_at` UTC epoch second when present.

Run this from `packages/cloud` after setting `STAGING_DOMAIN_NAME` to the hostname, `STAGING_HOSTED_ZONE_ID` to the dedicated zone ID, `STAGING_ARTIFACT_S3_URI` to the published archive, and `STAGING_ARTIFACT_SHA256` to its checksum. `AWS_REGION` defaults to `us-east-1`.

```bash
bun run generate:staging > mail-staging.cfn.json
bun run deploy:staging
bun run status:staging
```

The deploy command validates the zone and creates `MailServerStagingStack`. An existing stack causes the command to fail. `bun run diff:staging` compares the current template with the deployed stack. After creation, connect via Session Manager and check `sudo cloud-init status --wait`, `sudo systemctl is-active mail`, and `sudo /usr/local/sbin/mail-protocol-health-check --deploy-gate`.

The staging bootstrap installs ClamAV and waits for its initial signature databases before starting Mail. Mail connects through the local `/run/clamav/clamd.ctl` socket via its `clamav` supplementary group. Staging defers scannable writes when the scanner is unavailable. The watchdog submits a clean probe to the configured scanner using the Mail service identity. A failed probe appears as **Mail malware scanner** in service health. Check `systemctl is-active clamav-daemon clamav-freshclam` and the updater journal when diagnosing scanner readiness or signature age.

Verify the certificate and protocol endpoints on the staging hostname. Use port 587 for SMTP submission, 993 for IMAPS, 8443 for webmail, and 443 for EWS and ActiveSync. The provisioning listener uses loopback port 8099. Open a Session Manager port forwarding session for the synthetic signup and mailbox checks.

```bash
aws ssm start-session --target STAGING_INSTANCE_ID \
  --document-name AWS-StartPortForwardingSession \
  --parameters 'portNumber=8099,localPortNumber=8099'
```

With the tunnel open, run the deployed quota verifier from the Mail repository and supply the staging token in `MAIL_STAGING_PROVISIONING_TOKEN`. The TLS clients verify the staging hostname. The verifier allocates a fresh `qa-` mailbox prefix, checks exact storage and sending boundaries, and clears and suspends its synthetic mailboxes on exit. Keep the printed prefix with the deployment record.

```bash
python3 scripts/test-hosted-staging.py \
  --host mail.staging.example.com --domain staging.example.com \
  --provisioning-url http://127.0.0.1:8099
```

Use `--fixture /path/to/mail` to exercise the same client against a disposable TLS server. The verifier exercises SMTP submission, webmail, IMAP, EWS, ActiveSync, and private provisioning. The daemon restart, suspended SMTP retry, and UTC rollover tests continue to run in `scripts/test-hosted-limits.py --staging` with disposable daemon state.

For the local Stacks test process, set `MAIL_PROVISIONING_URL` to `http://127.0.0.1:8099`, `MAIL_PROVISIONING_TOKEN` to the staging token, `MAIL_FREE_SIGNUP_DOMAIN` to the staging mailbox domain, and `MAIL_WEBMAIL_ORIGIN` to the webmail URL from the stack output. Use a disposable signup database and configure the free-tier limits for the test. Record the deployed Mail, app, and SDK revisions and test results in #55, #57, and #61.

### Rehearse an additional hosted domain

Add each approved staging domain to `SMTP_LOCAL_DOMAINS`, then list it in
`SMTP_EXACT_MAILBOX_DOMAINS` and `SMTP_PROVISIONING_ADDITIONAL_DOMAINS`. These
settings take comma-separated domain names. Keep `SMTP_PROVISIONING_DOMAIN`
set to the primary domain and disable catch-all delivery. Restart Mail to
load the routing and provisioning settings.

Provision users with their full mailbox addresses. SMTP delivery and account
sign-in use the address's domain even when the same local part exists in
another domain. Create `postmaster@domain` through the operator CLI, since
the private provisioning API reserves that address. Check the additional
domain with the private `GET /provisioning/v1/domain?name=example.com`
endpoint before creating customer mailboxes. The daemon reports eligibility
from its configuration. Verify the account's DNS ownership claim in Stacks
before offering customer setup.

For team setup, the private `GET /provisioning/v1/team` takes the full
`mailbox` and provisioning `actor`. `POST /provisioning/v1/team` takes
those fields and the team `name`. The selected mailbox needs an active paid
service window on the additional domain. The first successful request
creates the team and appoints that mailbox as owner. Retries return the
existing team for the domain. The native domain rename moves that binding
with the mailbox addresses.

Run `python3 scripts/test-hosted-domains.py /path/to/mail` to exercise this
configuration with two disposable domains over native SMTP, IMAP, webmail,
EWS, and ActiveSync. Run `python3 scripts/test-hosted-cutover.py /path/to/mail`
to exercise local DNS MX changes, delivery through both cached routes, the
final IMAP delta, and recovery using a separate reverse checkpoint. Use a
public staging DNS zone to verify propagation and aligned authentication
before changing customer MX records.

### Inventory a hosted domain before transfer or retirement

Run the command from the daemon's working directory with the daemon's
configuration and `SMTP_DB_PATH`. Protect the output because it contains
mailbox and recovery addresses and sharing relationships.

```bash
umask 077
/opt/mail/mail-server domain inventory customer.example.com > native-inventory.json
```

The report reads one SQLite snapshot. It includes full mailbox addresses on
the exact domain, native assignment and operation IDs, access windows and
recovery settings, team membership and grants, forwards, and pending inbound
delivery. It identifies forwarding rules configured as Sieve so an operator
can review them before touching delivery. Local routing flags reflect the
configuration loaded by the command. Compare this with the Stacks billing
inventory to find reservations without a confirmed native result and mailbox
assignments without a matching billing record. Use both reports to plan the
transfer or retirement of the domain in #131.

### Retire the reviewed hosted mailboxes

Use the native operation ID issued by the Stacks billing lock and the exact
reviewed `domain inventory` file. Run against a daemon using the matching
Mail build and configuration. Drain pending delivery and resolve scheduled or
uncertain sends for those mailboxes before applying.

```bash
/opt/mail/mail-server domain retire native-operation-id native-inventory.json --yes
```

Mail verifies the current assignment roster and provisioning revisions, then
disables mailbox access and records the retirement as one SQLite transaction.
It preserves stored mail for operator recovery and reserves the retired
addresses. Keep the inventory file for retrying the same operation. Stacks can
read the receipt from the private `GET /provisioning/v1/retirement?id=…`
endpoint before releasing the billing seats and domain claim.

## Hosted mailbox diagnostics

Run the local report on the mailbox's Mail host. Use the daemon's working directory and database path. The staging stack uses `/var/lib/mail` for both.

```bash
cd /var/lib/mail
sudo -u mail-server env SMTP_DB_PATH=/var/lib/mail/smtp.db \
  /opt/mail/mail-server user:local hosted-status alice@staging.example.com
```

- Compare the observed enabled flag and byte quota with the requested values and recorded provisioning revision. If they differ, correlate the revision with the Stacks entitlement operation before making another provisioning change.
- For a full mailbox, check stored Maildir bytes, pending delivery reservations, and active file links. These share the byte budget. Moving messages to Trash keeps their bytes allocated.
- For a sending refusal, check recipients used today and the remaining allowance. The bucket uses UTC days. A counter dated in the future holds a metered allowance at zero. A legacy unlimited sending allowance appears as `recipients_remaining: null`.
- Pending, retry, and processing counts cover outbound queue rows attributed to this hosted mailbox. A suspended mailbox can still have queued deliveries. `outbound_queue: null` means the database has no hosted queue schema to inspect.

The report carries the observation time and an `audit_id`. Each successful report records `hosted.status` in `audit_log` with the effective operator UID and mailbox. The output is restricted to the mailbox identifier, operational state, and aggregate counters. Maildir and reservation counts may change while the daemon is delivering mail.

### Hosted mailbox write authority

Shared staging serves each hosted mailbox from one active Mail daemon. Keep
SMTP, webmail, IMAP, EWS, ActiveSync, and private provisioning on that authority.
It consists of the daemon's writable data directory, its SQLite database, and
the workers that claim and replay that database's work.

| State | Authority in the current deployment |
| --- | --- |
| Provisioning, service access, and operator sending holds | Mail's SQLite database holds the mailbox identity, provisioning revision, operation IDs, entitlement, and holds. The Stacks app sends revisioned changes to the private listener. |
| Storage quota | Admission accounts for committed Maildir bytes, pending local deliveries and active file links. A process-local mailbox mutation lock covers checks that span SQLite and the filesystem. |
| Recipient allowance | The canonical SQLite row records the recipient count by mailbox and UTC day. Admission and retry use this data and the original submission receipt. |
| Accepted delivery and replay | The daemon records delivery intent and replay state in SQLite before publishing accepted Maildir files. Webmail Outbox, outbound queue, and protocol receipts also belong to the active writer's state. |

A copied working directory has independent counters and receipts. A shared
Maildir path alone cannot share the mailbox mutation lock. Treat either
configuration as unverified for concurrent writers.

On one host, `mail serve` takes exclusive nonblocking locks on the local
`mail/` directory and on a `.mail-writer.lock` file beside each resolved
SQLite database it opens. The enabled Calendar and Contacts store
(`CALDAV_DB_PATH`) is covered alongside the SMTP database. One lock protects
both schemas when one daemon stores them in a single SQLite file. The daemon
holds its locks before SQLite opens, listeners start, or work replays. The
startup log identifies which store refused a second writer. Database symlinks
resolve to the same lock file. Mount each database directory as a unit and
keep the lock files between runs. Hard-linked database files are refused.
Stop the active daemon before upgrading from a version that lacks a guard,
replacing a data directory, or restoring the data. After a stop or crash
releases the locks, the replacement can reopen the stores and replay the
existing acceptance journal. Check the service log and configured data paths
if acquisition fails. Use a local filesystem and keep the same Maildir and
database pairing through promotion. The Docker image uses `/var/mail` as its working directory
so its relative Maildir lives on the same volume as the database. Preserve any
explicit working-directory override used by an existing installation. Two hosts
or independently copied directories require separate writer fencing.

Leave `SMTP_CLUSTER_ENABLED` unset or set it to `false` for hosted Mail.
Startup returns `HostedClusterUnsupported` when cluster mode is enabled
alongside the provisioning listener or when the SMTP database contains
hosted mailbox, provisioning, retirement, or erasure records. This check
also applies to a restored database with its provisioning listener off.

Before adding a listener or worker that could write the same hosted mailbox
from another daemon, complete [#179](https://github.com/mail-os/mail/issues/179).
A topology with one writer per mailbox can have additional listeners only if
every mutation, queue claim, and provisioning change reaches the same writer,
including sends through delegates and linked accounts. Use one stable mailbox
identity for routing. If the writer cannot be reached or ownership cannot be
confirmed, defer the operation without accepting or reserving it locally.
Promotion must fence the old writer before the replacement admits work.

Rehearse the intended routing, failover and recovery in a disposable topology
before changing shared staging. Race writes via different listeners for the last
byte and last recipient. Cut off the writer between reservation and commit,
then verify exactly one accepted delivery and receipt after failover. Check
that a suspension or sending hold applies to deferred work and that another
mailbox's allowance is independent. Record writer identity and state ownership
as well as responses across the protocols.

During a routing failure, compare the writer assigned to the mailbox, its
actual service instance, and the observed provisioning revision, reservations
and receipts. A missing writer, simultaneous writers, or inconsistent
observations blocks new writes to the affected mailbox. Stop routing admissions
and worker claims to the competing writers. Preserve their data and receipts
for reconciliation. Restore single-writer routing only after establishing
which state is authoritative. Then compare provisioning state and queue
receipts and rerun the [staging quota verifier](#native-mail-staging-on-aws).

### Hold outbound mail during a hosted abuse review

Run the following on the mailbox's Mail host with the same working directory
and database path as the status report. Supply only a non-sensitive case reference.

```bash
/opt/mail/mail-server user:local hosted-sending-hold alice@staging.example.com place case-1234
/opt/mail/mail-server user:local hosted-status alice@staging.example.com
/opt/mail/mail-server user:local hosted-sending-hold alice@staging.example.com release case-1234-reviewed
```

The report's `sending_held_since` field contains the placement time in Unix
seconds or `null` when no hold is active. The hold preserves access to existing
mail and inbound delivery under the current entitlement. New outbound admissions
fail. Previously accepted outbound retries pause. A scheduled webmail message
that comes due during the hold moves to Outbox review. Check both queues before
releasing the hold.

Quota and provisioning changes preserve the hold. Release leaves any suspension
or expired access in effect. Placement and release each commit an audit entry
with the effective operator UID and case reference. Resolve active holds with
the operator before rolling back to a binary that predates this command.

### Offboard a departed team owner

Use `mail team show` to confirm the departing owner and choose an existing
teammate. For a hosted team, the successor needs active paid service on the
team's domain. Run the handoff from the Mail host with the daemon's database.

```bash
/opt/mail/mail-server team offboard-owner studio alice@example.com bob@example.com operator-handoff-001
```

The handoff commits the replacement, membership removal, grant cleanup, and
`team.owner_handoff` audit entry together. Keep the operation ID with the ticket
and reuse it if the command's outcome is unclear. Confirm the successor can
manage the team, the departing mailbox has lost access to shared mail and
calendars, and outstanding invitations from the departing owner are gone.
Use the occupied-domain retirement workflow when the customer's mailbox itself
needs permanent retirement.

When a restore uses a snapshot from before an offboarding, repeat the recorded
command with its original operation ID on the restored database before opening
the listeners. Verify the successor's role and the former owner's shared
access on the restored host before returning it to service.

### Hosted service and export deadlines

The private v1 provisioning API accepts an optional `access_window` with
`service_until` and `read_until` as Unix seconds. Send the end of the verified
paid term plus grace as `service_until`, and the end of the export period as
`read_until`. The daemon applies both deadlines on access, including after
restart. It reports `full`, `read_only`, `expired`, or `disabled` for a
mailbox with a window. A missing window keeps the mailbox on its existing
operator-managed policy.

During export, SMTP temporarily defers new inbound mail, blocks outbound
submission, and holds queued outbound retries. Clients can read or download
existing data. After the export deadline SMTP refuses the recipient permanently
and authenticated access ends. An operator suspension takes precedence over
either deadline.

For an authorized export after suspension, use the
[portable mailbox export](../WEBMAIL.md#portable-mailbox-export). It preserves
Maildir messages, calendars, and contacts. Use managed retirement for a
hosted domain being released. Retirement disables access and retains data for
recovery. Hosted mailboxes are refused by `user:local delete` and the legacy
`gdpr delete` command. The legacy command only removes records from its SQLite
schema. The separate hosted erasure workflow is tracked in
[#188](https://github.com/mail-os/mail/issues/188).

For renewals, post `mailbox`, `actor`, `operation_id`, the next `revision`, and
`access_window` to `/provisioning/v1/mailbox/access`. The SDK calls this
`applyAccess`. It changes the deadlines and revision while preserving the
account's enabled flag, storage quota, and sending allowance. An older
provisioning client that omits the window on an update preserves the deadlines.

### Prepare a hosted mailbox erasure review

Use the daemon's working directory and database path. Copy the expected
assignment actor from the independently checked provisioning or billing
record. Use the canonical mailbox address and a case identifier containing
letters, numbers, periods, hyphens, or underscores. Keep the report private.

```bash
umask 077
sudo -u mail-server env SMTP_DB_PATH=/var/lib/mail/smtp.db \
  /opt/mail/mail-server user:local hosted-erasure-preflight \
  alice@customer.example.com mailbox-assignment-actor exit-case-19 > native-erasure-review.json
```

The command matches the mailbox and assignment actor. The report includes the
native user ID, initial provisioning operation when uniquely recorded, and
current provisioning revision. Compare the ID and initial operation with any
restored copy before using it. Investigate missing or ambiguous initial
operations with the provisioning ledger. The audit records the effective
operator UID, case, and observed identity.

The observation includes access and export deadlines, the retirement receipt
ID, sending hold, and counts for pending local delivery, interactive remote
delivery, the delivery queue, and webmail outbox. New delivery records carry
the authenticated hosted sender ID even when their envelope uses an external
sender address. For older records, an envelope or queue address match is only
a lead. Check any unresolved deliveries involving older external sender
identities against the available provider and submission records. A `null`
queue or outbox indicates that its schema is unavailable.

Use the report with the approved case, independently verified export recipient
and expiry, applicable retention and preservation holds, Stacks billing
assignment, Maildir and DAV inventory, and the backup and restore plan. A
sending hold controls sending. Review retention and preservation holds with
their owning system. Repeat the preflight after relevant state changes and
reconcile all evidence before an erasure operation. The supported actions are
portable export and managed retirement while [#188](https://github.com/mail-os/mail/issues/188)
tracks permanent erasure.

### Prepare a private archive for a reviewed hosted exit

Confirm the case and the recipient through the approved support channel. Run
preflight against the assignment after mail access has ended. Confirm that
its actor, native user ID, initial operation, and current revision match the
case. Use the approved handoff expiration as Unix seconds. The recipient
verification reference points to the support evidence without copying it into
Mail. Keep the reviewed JSON, archive, and receipt in a private directory.

```json
{
  "version": 1,
  "mailbox": "alice@customer.example.com",
  "assignment_actor": "mailbox-assignment-actor",
  "identity": {
    "native_user_id": 42,
    "initial_provisioning_operation": "initial-operation-id",
    "provisioning_revision": 3
  },
  "case_reference": "exit-case-19",
  "recipient_verification_reference": "support-verification-42",
  "recipient": "verified-recipient@example.net",
  "expires_at": 1800000000
}
```

Use the case values in place of the examples. Run the command against the same
Maildir, SQLite, and DAV data used for preflight. Use a quiesced set of stores
when the case requires a point-in-time archive across all three.

```bash
umask 077
/opt/mail/mail-server user:local hosted-erasure-export \
  /private/exit-case-19/review.json /private/exit-case-19/mailbox.tar \
  > /private/exit-case-19/receipt.json
```

The command checks the assignment and access before building the archive and
again before writing `hosted.erasure.export.prepared`. That audit entry preserves
the effective operator, stable assignment, case, verified recipient as supplied
by the operator, expiry, byte count, and SHA-256 of the archive. It records
preparation. The command links the private file only after the audit commits.
A successful receipt reports `private_archive_published` and the audit ID.

Use the approved delivery channel to enforce the expiry and record delivery
separately. If the command fails or is interrupted, keep the file private and
review its digest and audit entry before retrying with a new path. The command
preserves an existing destination. Keep the source mailbox and backup evidence
available for the retention and erasure review in [#188](https://github.com/mail-os/mail/issues/188).

### Verify a private export handoff

Create a private mode-0600 JSON file with `version: 1`, the `export_audit_id`
from the prepared export receipt, and the reviewed `mailbox`,
`assignment_actor`, `case_reference`, `recipient` and
`recipient_verification_reference`. Use the original recipient and case
evidence. Review a new export if either changes.

```sh
/opt/mail/mail-server user:local hosted-erasure-handoff \
  private-handoff-review.json private-export.tar approved-channel-staging.tar
```

The command checks the current mailbox assignment, the recorded recipient,
the original deadline and the archive byte count and digest. It stages a
mode-0600 copy only after writing the authorization audit. Retrying the same
export reuses its authorization and accepts an existing copy only when it
matches the audited bytes. The command refuses another tenant, changed input,
an expired export, or a destination containing other data.

The handoff receipt means the private copy is ready for the approved delivery
channel. Set that channel's expiration to the deadline in the receipt and
record delivery separately. Keep both private copies under the approved
retention policy. The handoff does not authorize erasure.

### Inventory retained stores before an erasure decision

Run the inventory from the daemon’s working directory using the same
`SMTP_DB_PATH`, `MAIL_ROOT`, and `CALDAV_DB_PATH`. Supply the same assignment
actor and case as preflight. Keep the report in the private case directory.

```bash
umask 077
/opt/mail/mail-server user:local hosted-erasure-inventory \
  alice@customer.example.com mailbox-assignment-actor exit-case-19 \
  > /private/exit-case-19/inventory.json
```

- `maildir` reports the canonical directory’s regular files and logical file
  bytes, including temporary files and hidden entries. It counts symbolic
  links without following them and flags a surviving short-name path for
  ownership review. `absent` refers to the configured location. `unavailable`
  means a full count could not be made.
- `sqlite.tables` counts owner rows and rows matched through known shared-store
  relationships. A `null` count marks an unavailable schema or ownership key.
  Zero means the query found no matching rows. `unscoped_tables` lists tables
  without an attribution query. Review those tables, derived search state,
  old delivery records, and all cross-mailbox dependencies before removal.
  A shared match may include records that another mailbox still needs.
- `dav` maps calendars, contacts, and related rows by durable native mailbox ID.
  `legacy_name_candidates` lists a count of possible name matches for manual
  ownership verification. `legacy_owner_unresolved`, `missing`, and
  `unavailable` require review. `not_configured` means the command received no
  explicit DAV path and found no file at the default path.
- `shared_backing` lists each Calendar, thread, and collection grant that
  involves the reviewed mailbox. It identifies the source or recipient role,
  peer by native ID, grant access, and backing collection when applicable.
  Use the report in the private case review before removing source data.
  Refresh older inventories that involve these grants. Review and reservation
  also reject changes in grant access when the row counts stay the same.
- `external_evidence_required` lists support and retention, external search,
  backup inventory, and hosted billing evidence to collect from their owning
  systems. The command also leaves these sources in the review when it finds
  no related native records.

The command opens the existing SQLite files without migrating them. It commits
an audit record with the observed counts and assignment before printing the
report. Counts reflect separate store observations, so take another inventory
from quiesced stores before relying on cross-store totals. Compare restored
copies with the current provisioning assignment and reconcile each outstanding
store under [#188](https://github.com/mail-os/mail/issues/188).

### Record the approved erasure review

After the mailbox has become unreadable, verify the requester and the approved
retention, backup, billing, search, and export decisions in the private support
case. Review any unscoped SQLite tables and unavailable ownership counts before
recording approval. Resolve outstanding delivery work before proceeding. Keep a
legal hold in force and leave the case pending if retention has not been cleared.

Save the reviewed inputs in a mode-0600 file. Use the current mailbox assignment,
the audit ID from its retained-store inventory, and a stable request ID unique
across mailboxes. Evidence references must be opaque identifiers resolvable from
the private case. Keep customer details and credentials out of these references.

```json
{
  "version": 1,
  "request_id": "erasure-request-19",
  "mailbox": "alice@customer.example.com",
  "assignment_actor": "mailbox-assignment-actor",
  "case_reference": "exit-case-19",
  "inventory_audit_id": 813,
  "retention_disposition": "cleared",
  "export_disposition": "resolved",
  "export_handoff_audit_id": 814,
  "evidence": {
    "authorization_reference": "support-authorization-19",
    "retention_reference": "retention-review-19",
    "backup_reference": "backup-disposition-19",
    "billing_reference": "billing-disposition-19",
    "search_reference": "search-disposition-19",
    "export_resolution_reference": "delivery-and-expiry-19"
  }
}
```

Use `resolved` when the private case records the approved channel's delivery
and access-expiry resolution. Use `not_requested` with a null handoff audit ID
and evidence of that decision when the case has no prepared export. A
`retention_disposition` of `held` prevents approval.

```bash
umask 077
/opt/mail/mail-server user:local hosted-erasure-review \
  /private/exit-case-19/review.json > /private/exit-case-19/review-receipt.json
```

The command compares the current Maildir, DAV and SQLite inventory with the
referenced audit and checks pending delivery in the SQLite transaction that records
`hosted.erasure.review.accepted`. It refuses an unresolved Maildir or DAV
owner, a stale inventory, unfinished or ambiguous delivery, and an export
handoff from another case or assignment. When retrying an identical eligible
request, use the same inputs to recover its audit ID. If the evidence or
inventory changes, review the new evidence and use a new request ID.

The receipt state is `review_recorded_data_retained`. The effective local
operator and evidence references accompany the stable assignment in the audit.
The native mailbox data and external stores remain in place. A future managed
removal must revalidate the approval, reconcile every retained store, and verify
scope again from quiesced Maildir and DAV data before making changes.

Reproduce export, handoff, and review acceptance on a disposable fixture with
`python3 scripts/test-hosted-erasure-export.py /path/to/mail`. The suite checks
retention holds, old snapshots, a separate tenant, stale inventories, queued
delivery, failed audit writes, and an identical retry.

### Reserve the reviewed mailbox for erasure

Before starting an erasure, confirm the private support case remains approved.
Use the original private review file and the audit ID from its accepted review
receipt. Use the same working directory and store paths as the inventory.

```bash
umask 077
/opt/mail/mail-server user:local hosted-erasure-begin \
  /private/exit-case-19/review.json 815 > /private/exit-case-19/start-receipt.json
```

The command rechecks the mailbox assignment, current store inventory, outstanding
delivery, and the accepted review. It disables the assignment, reserves its
address against reactivation and reassignment, and writes a
`hosted.erasure.started` audit record in one SQLite transaction. An identical
retry returns the same start receipt. A different request cannot take over the
reservation.

The receipt state is `erasure_started_data_retained`. Keep the receipt, its
review evidence, and the reservation with the paired restore records. A restore
from a snapshot containing the reservation preserves it. An older snapshot can
lack the reservation or the review. Reconcile it with the authoritative case
before making restored accounts accessible. The start command leaves the
Maildir, SQLite mailbox content, DAV, and external data in place for managed
removal after each store and backup disposition is verified.

Run `python3 scripts/test-hosted-erasure-export.py /path/to/mail` on disposable
data to verify the start, concurrent retry, failure rollback, old snapshot, and
provisioning refusal.

### Approve removal of shared source data

When a reserved mailbox is the source of shared threads, collections, a
shared inbox, or a shared calendar, inspect the affected grants before
deleting the underlying Maildir or DAV data. Use the same private case
review and start audit ID.

```bash
/opt/mail/mail-server user:local hosted-erasure-shared-release \
  /private/case/erasure-review.json START_AUDIT_ID maildir
```

Use `dav` for Calendar grants. The private report includes the scope digest
and whether approval is required. Compare outgoing grants in the reviewed
inventory and the current store. Resolve the remaining parties' retention
rights in the approved case. When a copy is required, retain it in
independently owned storage and verify access before approving source removal.

If approval is required, save a JSON file with mode `0600` using the digest
from that report and the case's approval reference.

```json
{
  "version": 1,
  "scope_sha256": "the-scope-sha256-from-the-report",
  "disposition": "release_source",
  "approval_reference": "approved-case-decision-id"
}
```

Run the same command with the decision file as its last argument. The
command records approval and returns its audit ID on a retry with the same
decision. Keep the record with the private case. Changes to the outgoing
grant scope require a fresh decision. For Maildir, the report also includes
digests of outgoing thread and collection records. Changes to the recorded
discussion, membership, message references, or reader permissions require a
fresh decision. Reconcile queued, uncertain, or partial shared replies before
approving the removal. The report includes each affected Outbox send ID,
actor ID, and delivery state, including replies queued by another mailbox for
this source.

Maildir and DAV removals check the approval for their own store before deleting content. The approval records
the operator's decision and leaves grants, discussion, and delivery records
in place for their own disposition.

For a Maildir case that requires a retained copy, use
`release_source_with_thread_archives` and a nonempty
`retained_thread_archives` list in the decision. Each entry includes
`source_share_id` and `peer_user_id` from the current Maildir scope report.
Only a peer with the original grant can receive a copy.

Stop the Maildir writers and use the running service's working directory
and configuration, including its Junk folder setting. Run the archive
command and preserve its receipt before removing the source.

```bash
umask 077
/opt/mail/mail-server user:local hosted-erasure-retain-threads \
  /private/case/erasure-review.json START_AUDIT_ID > /private/case/thread-archive-receipt.json
```

The command saves the shared view, followed reply excerpts, discussion,
and permitted attachment bytes in the recipient's own record. It returns
the same receipt on a retry for the same approval. Maildir removal verifies
each receipt checksum before deleting the source. After a successful removal,
the recipient can open each read-only copy from Shared Mail. The copy survives
deletion of the original grant. Recheck access as the recipient.

The command fails before committing any copy if the JSON and encoded
attachments exceed 32 MiB per approval or 64 MiB of retained archives per
recipient. Resolve those cases through the approved retention process before
removing the source.

For a DAV case that requires a retained copy, use the recipient's shared
CalDAV connection to copy the visible resources into a dedicated calendar
they own. Keep the source timezone and resource bytes. Use
`release_source_with_calendar_copies` in the decision and add a nonempty
`retained_calendar_copies` list. Each entry includes `source_share_id` and
`peer_user_id` from the private scope report and the numeric
`destination_calendar_id` from the peer's own calendar list.

DAV removal verifies the recipient can still read their mailbox, owns the
destination, and has the exact public resource bytes and timezone. A free/busy
grant does not authorize a retained event copy. The dedicated calendar may
contain only the resources visible through the source grant. If proof fails,
the source remains in place. The DAV transaction saves the verification evidence
with removal, so an interrupted audit can recover the same proof.

### Remove the reserved mailbox's canonical Maildir

This step permanently removes the canonical Maildir for one reserved mailbox.
Confirm that the approved case and its required export and backup dispositions
still apply. Stop all writers serving this working directory, including any
older Mail processes. Use the daemon's working directory and SMTP and DAV
database paths, and cross-check the start audit against the private case.

```bash
umask 077
/opt/mail/mail-server user:local hosted-erasure-maildir \
  /private/exit-case-19/review.json 816 > /private/exit-case-19/maildir-receipt.json
```

The command takes the daemon's exclusive Maildir lock. It refuses a different
root, a changed reviewed inventory, an unresolved legacy directory, crossed
mounts, symbolic links, and files shared through hard links. It journals the
directory identity, renames that directory under a private staging name, and
syncs the parent before it starts removing files.

Retry with the same review and start audit ID after an interruption. Preserve
the journal and any staged directory while resolving an error. If the original
or staged directory appeared again or changed identity, stop and reconcile the
working directory and backup pair. The completion receipt reports
`maildir_removed_other_stores_pending`. SQLite mailbox content, DAV, externally
derived data, and backup disposition still need their own reconciliation.
Removal of these active directory entries does not sanitize filesystem blocks
or historical snapshots.

Reproduce with `python3 scripts/test-hosted-erasure-maildir.py /path/to/mail`.
The disposable fixture covers daemon activity, a backup without the start
receipt, another tenant, changed paths, shared files, and interruption on both
sides of deletion.

### Remove active local search records

Keep the approved case and its Maildir removal receipt together. With the
same daemon stopped, run from its working directory with the same
`SMTP_DB_PATH` and `MAIL_ROOT` used for Maildir removal.

```bash
umask 077
/opt/mail/mail-server user:local hosted-erasure-search \
  /private/exit-case-19/review.json 816 > /private/exit-case-19/local-search-receipt.json
```

The command verifies the Maildir receipt and checks for a restored directory
under the same writer lock. One SQLite transaction removes the reserved
native account's Webmail search documents and its ActiveSync search key,
checks the full-text index against its content table, and commits counts
and an audit receipt. A failed check rolls back the transaction. Retry with
the same review and start ID to retrieve the same receipt.

Record `local_search_removed_other_stores_pending` as completion of the
active SQLite search step. Reconcile Typesense documents and their retained
pending work and revisions separately. The remaining review includes
SQLite WAL and older index segments, backups, and the other active stores.

Run `python3 scripts/test-hosted-erasure-search.py /path/to/mail` on a
disposable installation. The fixture searches genuine SMTP-delivered mail
in both accounts, forces rollback on a stale full-text index and an audit
failure, then checks the peer's search and retry receipt after removal.

### Reconcile active Typesense documents

When the mailbox was indexed in Typesense, confirm the approved case identifies
the live Typesense service and each separately operated copy. Keep every Mail
writer connected to that service stopped. Run from the same working directory
and SQLite database used by the earlier steps. Use the service's Typesense
host and port and an operator credential with collection metadata, document
export, and document deletion access. Supply the reviewed host and port from
the private case to compare against the command environment.

```bash
umask 077
/opt/mail/mail-server user:local hosted-erasure-typesense \
  /private/exit-case-19/review.json 816 127.0.0.1 8108 \
  > /private/exit-case-19/typesense-receipt.json
```

The command checks `messages`, `messages_v2`, and `messages_v3`. It records the
approved endpoint and collection creation times before mutating the index.
A filtered metadata export finds candidate documents. Each deletion uses a
verified native document ID whose stored owner exactly matches the reserved
mailbox. This preserves neighboring addresses even when Typesense normalizes
their punctuation or case to the same search value.

Retry with the same review, start audit, and endpoint after interruption. Keep
the recorded intent and investigate collection identity changes before resuming
the case. The command verifies the target is absent from the selected active
collections before committing removal of that owner's pending index work and
checkpoints. Keep the `typesense_removed_other_stores_pending` receipt with the
case. Reconcile index snapshots, retained database history, and other services
under the same approved retention and backup policy.

Run `python3 scripts/test-hosted-erasure-typesense.py /path/to/mail --typesense-server /path/to/typesense-server`
against disposable fixtures to reproduce the real Typesense 30.2 rehearsal.

### Remove active Calendar and Contacts data

Use the approved review and the completed Maildir receipt. Stop Mail and any
other writers using the same DAV database. Supply the exact path configured
in `CALDAV_DB_PATH`, or `./caldav.db` when the daemon uses its default.
Confirm this path and its paired SMTP database against the approved case.

```bash
umask 077
/opt/mail/mail-server user:local hosted-erasure-dav \
  /private/exit-case-19/review.json 816 /opt/mail/caldav.db \
  > /private/exit-case-19/dav-receipt.json
```

The command verifies the reviewed database identity and scope, then removes
the mapped owner's CalDAV calendars and events, CardDAV address books and
contacts, contact addresses and numbers, reminder dismissals, and DAV owner
record. A known empty scope receives its own receipt. It refuses an unresolved
legacy owner, an unexpected DAV table, and a replacement or linked file.
Historical inventories without a database stamp use the recorded counts and
explicitly confirmed configured path before the first attempt.

Keep both databases together while retrying. The DAV transaction verifies
child removal before deleting each parent, then commits a receipt marker and
ID high-water marks with the deletion. A failed SMTP audit can be retried
with the same review and start ID. The completed receipt reports
`dav_owned_data_removed_other_stores_pending`. Continue reconciliation of
SQLite history, shared-calendar records in the SMTP database, and backups.

Run `python3 scripts/test-hosted-erasure-dav.py /path/to/mail` with the
disposable TLS fixtures. It covers transaction rollback, an audit interruption
after the DAV commit, peer resource preservation, and ID allocation after
restart.

### Reconcile live shared SQLite records

After Maildir removal and any outgoing shared Calendar removal, inspect the
live shared records for the same reserved mailbox. Stop the Mail daemon and
use its working directory and SQLite configuration.

```bash
umask 077
/opt/mail/mail-server user:local hosted-erasure-shared-sqlite \
  /private/case/erasure-review.json START_AUDIT_ID
```

The plan lists live share and delegation edges, owner collection and workflow
counts, and the drafts, Outbox IDs, and reply claims that remain as delivery
evidence. For an erased delegate, it also counts assignments to be cleared
in the peer's inbox. The plan keeps message and draft bodies private.
Resolve pending, partial, or uncertain shared replies before proceeding.

Approve the exact plan using `version` 1, its `scope_sha256`, and the case's
`approval_reference` in a private JSON file. Pass that file as the final
argument to the same command. The operation verifies the source-release
receipts and archived copies, removes the approved live records, and saves
one audited receipt in the same transaction. A retry with the same approval
returns that receipt. Draft and delivery records remain in their own
mailboxes with their original payloads. Revoking the grants prevents their
shared reply contexts from being used for new sends. Team membership and
ownership remain available for the team's separate handoff.

### Remove mailbox-private SMTP SQLite records

After completing Maildir removal, keep the daemon stopped and run the
following command as the service account with the same configured SMTP
database and mail root used for the reservation.

```bash
/opt/mail/mail-server user:local hosted-erasure-sqlite \
  /private/case/erasure-review.json START_AUDIT_ID
```

The command removes the reserved mailbox's private reset and sign-in data,
MFA records, client passwords, unlinked browser sessions, published file
and message snapshot links, personal attention and notification data,
category rules, calendar workflow preferences and tasks, IMAP UID and
generation data, and ActiveSync and EWS sync metadata. The deletion and
receipt are committed together. A retry checks the same live scopes and
returns the original audit ID. The deletion count includes any generation
tombstones that the IMAP delete trigger creates and the command then removes.

The receipt state is `private_sqlite_removed_other_data_pending`. The
disabled account and its reservation remain in place. Reconcile private
collections and their shared references, drafts and uploads, assistant
permissions and audit records, routing and accepted delivery records,
SQLite recovery history, and backups separately.

Run `python3 scripts/test-hosted-erasure-sqlite.py /path/to/mail` with the
disposable TLS fixture. It checks transaction rollback, tombstone cleanup,
receipt retry, and peer preservation through a daemon restart.

### Revoke remaining linked browser sessions

After the private SQLite step, keep Mail stopped and use the same review
and start audit ID to revoke the mailbox's combined-inbox links.

```bash
/opt/mail/mail-server user:local hosted-erasure-links \
  /private/case/erasure-review.json START_AUDIT_ID
```

The command detaches the mailbox in both directions. It revokes the
credentials minted for each removed link and clears any residual sessions
of the departing mailbox. The peer's own sign-ins and unrelated saved
links keep working. Resolve unsettled Outbox records tied to an affected
link and investigate unexpected session ownership before retrying.

The receipt reports `linked_sessions_revoked_other_data_pending` and
keeps a stable audit ID on retry. The counts cover revoked links and
departing mailbox sessions that remain after the link credentials are
revoked. Other shared records and older SQLite copies require separate
reconciliation.

Run `python3 scripts/test-hosted-erasure-links.py /path/to/mail` with the
disposable TLS fixture to verify both link directions, refusal, rollback,
and peer access after restart.

### Remove live private mailbox content

After the Maildir, local search, private SQLite, shared SQLite, and linked
session steps are verified, keep Mail stopped and run the following command
with the same private review file and start audit ID.

```sh
/opt/mail/mail-server user:local hosted-erasure-private-content \
  /root/cases/erasure-review.json START_AUDIT_ID
```

This transaction deletes private drafts and unreferenced uploads, notes,
labels, groups, per-mailbox routing and retention settings, and message
references with no retained delivery dependency. Resolve unfinished EWS
sends and sender-review moves before removing the Maildir. Shared and
delegated drafts, terminal Outbox and delivery records, and references
or uploads they still use remain available for their separate disposition.
Unknown webmail record kinds remain in place.

Save the resulting `private_content_removed_retention_pending` receipt
with the case. It includes the verified step audit IDs and counts of
removed and retained rows. A retry returns the original audit ID and
counts after rechecking the live store. A partial restore that reintroduces
private rows blocks confirmation. Check the outstanding case evidence
separately for DAV, external search, retained active records, SQLite WAL
and historical pages, backups and restoration, billing, and support.

Run `python3 scripts/test-hosted-erasure-private-content.py /path/to/mail`
to verify the disposable TLS case, including audit rollback and peer access.

### Record the hosted erasure closeout

Keep Mail stopped and use the same working directory, database paths,
search configuration, private review and start audit ID. Run the
closeout without a decision to verify the recorded Maildir, search,
SQLite, shared-record, linked-session and private-content steps. It
also checks the current DAV and Typesense stores when configured.

```sh
umask 077
mail user:local hosted-erasure-closeout /secure/review.json START_AUDIT_ID \
  > /secure/closeout-scope.json
```

The scope lists the native audit IDs, retained SQLite tables with scoped
counts and digests, and tables that require a separate ownership review.
It includes only fingerprints of retained rows. Inspect the local and
external stores listed in the approved case before recording a decision.

Use a private JSON file with version 1, the reported `scope_sha256` and a
unique `approval_reference`. Include `external_search_reference` and
`sqlite_scope_reference` for the evidence covering independently operated
search and unmapped SQLite tables. Record dispositions for `sqlite_history`,
`hosted_billing`, `support_records` and `backups.disposition`.
Each disposition has a `state` and evidence `reference`. Use `removed`,
`retention_required` or `retained_until`. An expiring disposition requires a
future `retain_until` timestamp in Unix seconds.

Include `backups.retained_snapshots` and, when any snapshots remain, a
`backups.restore_verification_reference` to the older-snapshot verification
record. After verifying the recovered stores with `verify-erasure-checkpoint`,
bind the signed source and replay checkpoints to the original case. Obtain
the scope, signing key, both file digests and earliest observation from
the independently retained recovery record.

```sh
mail backup verify-erasure-replay-chain /secure/source-checkpoint.json \
  /secure/replay-checkpoint.json /secure/original-smtp.db /secure/review.json \
  --scope TRUSTED_SCOPE --public-key TRUSTED_ED25519_PUBLIC_KEY \
  --expected-sha256 SOURCE_SHA256 --replay-sha256 REPLAY_SHA256 \
  --not-before EARLIEST_UNIX_TIME > /secure/replay-evidence.json
```

The verifier reads the original case and confirms that both signed checkpoints
cover its assignment and the approved peer copies. Keep the report and both
checkpoints in the private case record. Use the report's `evidence_sha256`
as `backups.restore_verification_reference`.

In `retained_records`, list each table from the verified scope once
with its `table` and retention `disposition`. Use the approved evidence for
required audit records and remaining delivery, team or reservation data.
Match the recorded scope to decisions from the operators responsible for
the backup catalog, storage history, billing and support.

```sh
mail user:local hosted-erasure-closeout /secure/review.json START_AUDIT_ID \
  /secure/closeout-decision.json > /secure/closeout-receipt.json
```

The final transaction rechecks the scope, records one audit entry and issues
a receipt with the native verification and external evidence references.
An identical retry returns the same receipt on the same scope. A changed
retained row, missing deletion proof or returned live data blocks that
approval. The recorded retention dates apply to the named evidence. Recheck
the affected stores and obtain a current decision when a scope changes.

Run `python3 scripts/test-hosted-erasure-closeout.py /path/to/mail` with
disposable TLS mailboxes and an actual backup archive. Add
`--typesense-server /path/to/typesense-server` for the external search case.

### Check hosted erasure before restoring Mail

Extract the backup into isolated storage. Run the portable message identity
check and then compare the recovered SMTP, Maildir, and DAV data with the
current lifecycle database. Use the protected SMTP database from the original
server as the authority. Its path must come from the trusted recovery
environment, outside the extracted archive. For hosted backups, the two
databases must have a shared immutable provisioning identity.

```sh
mail backup rebind-local /restore/smtp.db /restore/mail
mail backup verify-erasure-restore /opt/mail/smtp.db /restore/smtp.db \
  /restore/mail /restore/caldav.db
```

Supply the DAV database whenever the reviewed case had a DAV store. The check
compares exact mailbox identities and audit receipts, confirms the reservation
still blocks access, and inspects the restored stores for erasure regressions.
The result records the authority digest, latest verified reservation, number
of reservations, and time of the check. Keep that result with the recovery
record. Repeat the check immediately before promotion while the authoritative
lifecycle state is frozen.

Recoveries with missing authority, an unfinished case, an older reservation
snapshot, or returned mailbox data need operator reconciliation. Keep the
extracted instance offline in those cases and retain it for the authorized
recovery workflow. The legacy S3 restore can only promote a compatible
installation with a current lifecycle database and no erasure reservations.

The Restic restore check uses `/opt/mail/smtp.db` by default, or the
`MAIL_RESTORE_AUTHORITATIVE_DB` path from the protected restore environment.
Where the deployment uses a different database path, configure the canonical
live database. Backup expiry and off-host lifecycle recovery are tracked
separately in the hosted erasure case.

### Recover the erasure authority from off-host storage

A signed checkpoint lets a recovery host verify a backup after losing
access to the original SMTP database. The checkpoint contains digests of
the current provisioning identities, reservation reviews and receipts,
plus the audit sequence and observation time. Keep its signing seed in
the publisher's secret store, outside the Mail backups and off the
recovery host. For an initial seed, use `openssl rand -hex 32` and store
the result in a private file with mode 0600. Record the publisher's
public key in the trusted recovery configuration.

Freeze lifecycle writes before recording the recovery checkpoint. Use the
protected current database, a deployment-specific scope and a private
output directory.

```sh
umask 077
mail backup seal-erasure-authority /opt/mail/smtp.db production-mail \
  /secure/mail-erasure.seed > /secure/mail-erasure-authority.json
```

Copy the JSON to authenticated off-host storage with an independent
retention policy. Verify the digest of the retrieved copy before
publishing its SHA-256 and earliest accepted observation time to the
trusted recovery record. Keep that control record separate from the
snapshot under review. Advance the pinned digest only after the new
checkpoint is durable. Use the current recovery record for every
verification. If it predates later lifecycle changes, reconcile those
changes from authoritative support records before promoting the backup.

On the recovery host, use the pinned public key, scope, digest and
freshness floor from the independent control record. The checkpoint
itself supplies the signed evidence.

```sh
mail backup verify-erasure-checkpoint /secure/mail-erasure-authority.json \
  /restore/smtp.db /restore/mail /restore/caldav.db \
  --scope production-mail --public-key "$TRUSTED_PUBLISHER_PUBLIC_KEY" \
  --expected-sha256 "$TRUSTED_CURRENT_CHECKPOINT_SHA256" \
  --not-before "$TRUSTED_EARLIEST_OBSERVATION_SECONDS"
```

The restore receipt reports the verified checkpoint digest and
observation time. A missing pin, mismatched deployment, older checkpoint,
unfinished case or returned mailbox data blocks verification. For the
automated Restic check, set `MAIL_RESTORE_ERASURE_CHECKPOINT`,
`MAIL_RESTORE_ERASURE_SCOPE`, `MAIL_RESTORE_ERASURE_PUBLIC_KEY`,
`MAIL_RESTORE_ERASURE_SHA256` and `MAIL_RESTORE_ERASURE_NOT_BEFORE`
in the protected recovery environment. The signed check uses the same
SMTP, Maildir and DAV verification as the live-database check.

### Replay an approved erasure into an older backup

Keep the original archive and extract a working copy on the isolated
recovery host. Keep listeners stopped throughout the replay. Obtain a new
review of the restored data through the same authorization and retention
process as the original case. Keep the original mailbox, assignment actor,
request ID and case reference in the private review. The expected
publisher key, scope, source checkpoint digest and observation floor come
from the independent recovery record.

From the extracted directory, use the review to match and disable the
original assignment. The command locks the restored Maildir and preserves
linked sessions for the reviewed linked-session step.

```sh
cd /restore
mail backup rebind-local smtp.db mail
mail backup check-erasure-replay-target /secure/original-authority.json smtp.db \
  /secure/recovery-review.json --isolate-maildir mail \
  --scope production-mail --public-key "$TRUSTED_PUBLISHER_PUBLIC_KEY" \
  --expected-sha256 "$TRUSTED_CURRENT_CHECKPOINT_SHA256" \
  --not-before "$TRUSTED_EARLIEST_OBSERVATION_SECONDS"
```

Run the inventory, approval, reservation, and removal steps against the
isolated SMTP, Maildir and DAV stores. Record the fresh inventory audit ID
and approval evidence in the review before recording it. Use the local start
audit ID for the removal steps. Complete every case in the signed source
checkpoint. Preserve the approved peer-owned Mail and Calendar copies and
reconcile pending deliveries before removal. An extra case, changed
assignment, incomplete step or changed peer copy blocks certification.

With the recovery record approved, certify the replay in the trusted
publishing environment. Use the signing seed corresponding to the pinned
public key. Keep the replayed backup offline until verification succeeds.

```sh
umask 077
mail backup seal-erasure-replay /secure/original-authority.json /restore/smtp.db \
  /restore/mail /secure/mail-erasure.seed /restore/caldav.db \
  --scope production-mail --public-key "$TRUSTED_PUBLISHER_PUBLIC_KEY" \
  --expected-sha256 "$TRUSTED_CURRENT_CHECKPOINT_SHA256" \
  --not-before "$TRUSTED_EARLIEST_OBSERVATION_SECONDS" \
  --approval-reference recovery-case-123 > /secure/replay-authority.json
```

Publish the replay checkpoint and its exact digest through the independent
recovery record. Run `verify-erasure-checkpoint` against the prepared backup
with that new pin. The receipt identifies the original checkpoint and the
recovery approval. It checks the resulting stored state and the retained
peer copies again. Keep the original and replay receipts with the recovery
case. Earlier signed checkpoint versions remain usable for verification.
Issue a current checkpoint with replay evidence before starting a replay.

## Local mailbox directory upgrade

Back up the Maildir and SQLite database together before upgrading a server with older ActiveSync clients. On startup, the server checks for full-address local accounts that still have mail under a short directory name such as `mail/alice`. It moves eligible messages to `mail/alice@example.com` before opening the protocol listeners. It also moves messages in a canonical custom folder's nested slots into the folder path exposed by IMAP and webmail. ActiveSync, IMAP, webmail, and EWS then read from the canonical mailbox. The upgrade retains existing message flags and client identifiers when it can reconcile both directories.

The startup log records the affected mailbox and any residual archive under `mail/.relocated-maildir-*`. If the short name has multiple owners, a folder layout conflicts, or a message filename already exists at the destination, both roots stay on disk and clients use the canonical root. Review the warning and establish ownership and file identity from the backup before resolving the conflict. When rolling back to a version that reads short-name directories, restore the matching pre-upgrade database and Maildir snapshot together.

---

## Table of Contents

1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Initial Deployment](#initial-deployment)
3. [Upgrade Procedures](#upgrade-procedures)
4. [Rollback Procedures](#rollback-procedures)
5. [Database Operations](#database-operations)
6. [TLS Certificate Management](#tls-certificate-management)
7. [Backup and Restore](#backup-and-restore)
8. [Monitoring Setup](#monitoring-setup)
9. [Performance Tuning](#performance-tuning)
10. [Incident Response](#incident-response)
11. [Maintenance Windows](#maintenance-windows)

---

## Pre-Deployment Checklist

### Infrastructure Requirements

- [ ] Server with minimum 2GB RAM, 2 CPU cores
- [ ] Persistent storage with minimum 20GB available
- [ ] Network connectivity (ports 25, 587, 8080, 8081)
- [ ] DNS records configured (MX, SPF, DKIM, DMARC)
- [ ] TLS certificates obtained (Let's Encrypt or commercial CA)
- [ ] Reverse proxy configured (nginx, Caddy, or HAProxy)

### Software Requirements

- [ ] Operating system: Linux (Ubuntu 22.04+ recommended)
- [ ] Zig 0.15.1 installed (for building from source)
- [ ] SQLite 3.35+ installed
- [ ] systemd for service management
- [ ] Prometheus (optional, for metrics)
- [ ] Log aggregation system (optional, for centralized logging)

### Security Requirements

- [ ] Firewall rules configured
- [ ] SELinux/AppArmor policies reviewed
- [ ] Service user account created (`smtp` user)
- [ ] File permissions set correctly (600 for database, 644 for binaries)
- [ ] Secrets management configured (environment variables or vault)

### Configuration Prepared

- [ ] Configuration profile selected (staging/production)
- [ ] Environment variables documented
- [ ] Database initialization plan
- [ ] Initial user accounts planned
- [ ] Filter rules prepared

---

## Initial Deployment

### Step 1: Build Application

```bash
# Clone repository
git clone https://github.com/yourusername/mail.git
cd mail

# Checkout stable version
git checkout v0.28.0

# Build release binary
zig build -Doptimize=ReleaseSafe

# Verify build
./zig-out/bin/mail --version
```

**Expected Output:**
```
Mail Server v0.28.0
Built with Zig 0.15.1
```

**Time:** ~5 minutes

---

### Step 2: Create Service User

```bash
# Create smtp user and group
sudo useradd -r -s /bin/false smtp

# Create directories
sudo mkdir -p /opt/mail
sudo mkdir -p /var/lib/mail
sudo mkdir -p /var/log/mail
sudo mkdir -p /etc/mail

# Set ownership
sudo chown -R smtp:smtp /var/lib/mail
sudo chown -R smtp:smtp /var/log/mail
sudo chown -R smtp:smtp /etc/mail
```

**Time:** 2 minutes

---

### Step 3: Install Application

```bash
# Copy binary
sudo cp ./zig-out/bin/mail /opt/mail/
sudo cp ./zig-out/bin/user-cli /opt/mail/

# Set permissions
sudo chown root:smtp /opt/mail/mail
sudo chmod 750 /opt/mail/mail

# Verify installation
/opt/mail/mail --version
```

**Time:** 1 minute

---

### Step 4: Configure Application

```bash
# Create configuration file
sudo tee /etc/mail/config.env << 'EOF'
# Mail Server Configuration - Production
SMTP_PROFILE=production

# Server Settings
SMTP_HOST=0.0.0.0
SMTP_PORT=2525
SMTP_HOSTNAME=mail.example.com
SMTP_MAX_CONNECTIONS=2000

# Timeouts
SMTP_TIMEOUT_SECONDS=300
SMTP_DATA_TIMEOUT_SECONDS=600
SMTP_COMMAND_TIMEOUT_SECONDS=300
SMTP_GREETING_TIMEOUT_SECONDS=30

# Message Limits
SMTP_MAX_MESSAGE_SIZE=26214400
SMTP_MAX_RECIPIENTS=100

# Authentication
SMTP_ENABLE_AUTH=true
SMTP_DB_PATH=/var/lib/mail/smtp.db

# Security
SMTP_ENABLE_TLS=false
SMTP_REQUIRE_TLS=false

# Spam Prevention
SMTP_ENABLE_DNSBL=true
SMTP_ENABLE_GREYLIST=true

# Rate Limiting
SMTP_RATE_LIMIT_PER_IP=200
SMTP_RATE_LIMIT_PER_USER=100
SMTP_RATE_LIMIT_CLEANUP_INTERVAL=3600

# Logging
SMTP_ENABLE_JSON_LOGGING=true

# Tracing
SMTP_ENABLE_TRACING=true
SMTP_TRACING_SERVICE_NAME=smtp-prod-us-east-1

# Webhooks (optional)
# SMTP_WEBHOOK_URL=https://api.example.com/webhook
# SMTP_WEBHOOK_ENABLED=true
EOF

# Secure configuration file
sudo chown root:smtp /etc/mail/config.env
sudo chmod 640 /etc/mail/config.env
```

**Time:** 3 minutes

---

### Step 5: Initialize Database

```bash
# Set database path
export SMTP_DB_PATH=/var/lib/mail/smtp.db

# Initialize database (migrations run automatically on first start)
# Create initial admin user
sudo -u smtp /opt/mail/user-cli create \
  admin@example.com \
  --password "$(openssl rand -base64 32)" \
  --email admin@example.com

# Verify database
sudo -u smtp sqlite3 $SMTP_DB_PATH "SELECT username, enabled FROM users;"
```

**Expected Output:**
```
admin@example.com|1
```

**Time:** 2 minutes

---

### Step 6: Configure systemd Service

```bash
# Create systemd service unit
sudo tee /etc/systemd/system/mail.service << 'EOF'
[Unit]
Description=Mail Server
Documentation=https://github.com/yourusername/mail
After=network.target

[Service]
Type=simple
User=smtp
Group=smtp
WorkingDirectory=/opt/mail
EnvironmentFile=/etc/mail/config.env
ExecStart=/opt/mail/mail
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/mail /var/log/mail
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Resource limits
LimitNOFILE=65536
LimitNPROC=512

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
sudo systemctl daemon-reload
```

**Time:** 2 minutes

---

### Step 7: Configure Reverse Proxy (nginx)

```bash
# Install nginx if not present
sudo apt-get install -y nginx certbot python3-certbot-nginx

# Create nginx configuration
sudo tee /etc/nginx/sites-available/mail << 'EOF'
# Mail Server - TLS Termination Proxy

upstream smtp_backend {
    server localhost:2525 max_fails=3 fail_timeout=30s;
}

server {
    listen 25;
    listen 587;

    server_name mail.example.com;

    # TLS configuration
    ssl_certificate /etc/letsencrypt/live/mail.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mail.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Proxy to SMTP backend
    location / {
        proxy_pass http://smtp_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts for SMTP
        proxy_connect_timeout 60s;
        proxy_send_timeout 600s;
        proxy_read_timeout 600s;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/mail /etc/nginx/sites-enabled/mail

# Test configuration
sudo nginx -t

# Reload nginx
sudo systemctl reload nginx
```

**Time:** 5 minutes

---

### Step 8: Obtain TLS Certificates

```bash
# Obtain Let's Encrypt certificate
sudo certbot --nginx -d mail.example.com

# Verify certificate
sudo certbot certificates

# Setup auto-renewal
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer
```

**Time:** 3 minutes

---

### Step 9: Start Service

```bash
# Validate configuration
sudo -u smtp SMTP_PROFILE=production /opt/mail/mail --validate-only

# Start service
sudo systemctl start mail

# Check status
sudo systemctl status mail

# Enable auto-start on boot
sudo systemctl enable mail

# View logs
sudo journalctl -u mail -f
```

**Expected Log Output:**
```json
{"timestamp":1698765432,"level":"INFO","service":"mail","hostname":"prod-smtp-01","message":"=== Mail Server Starting ==="}
{"timestamp":1698765432,"level":"INFO","service":"mail","hostname":"prod-smtp-01","message":"Configuration loaded and validated successfully:"}
{"timestamp":1698765432,"level":"INFO","service":"mail","hostname":"prod-smtp-01","message":"Mail Server listening on 0.0.0.0:2525"}
```

**Time:** 3 minutes

---

### Step 10: Verify Deployment

```bash
# Check health endpoint
curl -s http://localhost:8081/health | jq .

# Check metrics endpoint
curl -s http://localhost:8081/metrics | head -20

# Test SMTP connection
telnet localhost 25
# Expected: 220 mail.example.com ESMTP Service Ready
# Type: QUIT

# Send test email
echo "Subject: Test Email

This is a test message." | sendmail -f test@example.com recipient@example.com

# Check logs for successful delivery
sudo journalctl -u mail | grep "Message received"
```

**Time:** 5 minutes

**Total Deployment Time:** ~31 minutes

---

## Upgrade Procedures

### Start a production release from GitHub

Changes merged to `main` run CI. Start a production deployment separately
after verifying the selected commit on staging and checking that the release
and rollback prerequisites are met. For a release that migrates legacy CalDAV
or CardDAV ownership, verify the collection owners and take a paired Mail and
DAV checkpoint before deployment. [Legacy DAV ownership checklist](https://github.com/mail-os/mail-app/issues/2)

```bash
gh workflow run deploy.yml --repo mail-os/mail --ref main -f revision=FULL_VERIFIED_COMMIT_SHA
```

The selected ref must point to the verified commit when you start the workflow.
If the ref has advanced, verify the new revision before starting its deployment.

### Standard Upgrade (Rolling Update)

**Pre-requisites:**
- [ ] New version tested in staging environment
- [ ] Backup completed
- [ ] Maintenance window scheduled (optional for rolling update)
- [ ] Rollback plan prepared

### Step 1: Pre-Upgrade Checks

```bash
# Check current version
/opt/mail/mail --version

# Check service health
curl -s http://localhost:8081/health | jq .status

# Record current metrics
curl -s http://localhost:8081/stats > /tmp/pre-upgrade-stats.json

# Backup database
sudo -u smtp sqlite3 /var/lib/mail/smtp.db ".backup /var/lib/mail/smtp-backup-$(date +%Y%m%d-%H%M%S).db"

# Verify backup
sudo -u smtp sqlite3 /var/lib/mail/smtp-backup-*.db "PRAGMA integrity_check;"
```

**Time:** 3 minutes

---

### Step 2: Build New Version

```bash
# Fetch new version
cd /tmp
git clone https://github.com/yourusername/mail.git mail-new
cd mail-new
git checkout v0.29.0

# Build
zig build -Doptimize=ReleaseSafe

# Verify build
./zig-out/bin/mail --version
# Expected: Mail Server v0.29.0
```

**Time:** 5 minutes

---

### Step 3: Deploy New Binary

After stopping Mail and its other writers, capture and verify the complete
recovery point before installing the new executable. Include both databases,
Maildir, and the matching configuration using the [backup procedure](#backup-and-restore).

```bash
# Stop service
sudo systemctl stop mail

# Capture and verify the complete recovery point here.

# Backup old binary
sudo cp /opt/mail/mail /opt/mail/mail.v0.28.0

# Install new binary
sudo cp /tmp/mail-new/zig-out/bin/mail /opt/mail/
sudo chown root:smtp /opt/mail/mail
sudo chmod 750 /opt/mail/mail

# Validate new version
/opt/mail/mail --version

# Test configuration
sudo -u smtp SMTP_PROFILE=production /opt/mail/mail --validate-only
```

**Time:** 2 minutes

---

### Step 4: Start and Verify

```bash
# Start service
sudo systemctl start mail

# Monitor startup
sudo journalctl -u mail -f -n 50

# Wait 30 seconds for warm-up
sleep 30

# Check health
curl -s http://localhost:8081/health | jq .

# Verify version
curl -s http://localhost:8081/stats | jq .

# Test SMTP connection
echo "QUIT" | telnet localhost 25
```

**Time:** 3 minutes

---

### Step 5: Post-Upgrade Validation

```bash
# Compare metrics (should be similar)
curl -s http://localhost:8081/stats > /tmp/post-upgrade-stats.json
diff /tmp/pre-upgrade-stats.json /tmp/post-upgrade-stats.json

# Send test message
echo "Subject: Post-Upgrade Test

Upgrade to v0.29.0 successful" | sendmail test@example.com

# Monitor for errors
sudo journalctl -u mail --since "5 minutes ago" | grep -i error

# Check database migrations
sudo -u smtp sqlite3 /var/lib/mail/smtp.db "SELECT version, name FROM schema_migrations ORDER BY version DESC LIMIT 5;"
```

**Time:** 3 minutes

**Total Upgrade Time:** ~16 minutes

---

## Rollback Procedures

### When to Rollback

- Critical bugs discovered in new version
- Performance degradation > 20%
- Database corruption detected
- Service health degraded/unhealthy

### Rollback Steps

1. Pause intake or allow the upstream relay to queue mail. Stop Mail and any
   other writers, then capture a new recovery point with both databases,
   Maildir, and the matching configuration. Keep the pre-upgrade checkpoint
   and the current recovery point available throughout the rollback.
2. Reopen the current data with the previous executable on an isolated copy.
   Verify the readers and workers you intend to run, including every pending
   Outbox format. A binary-only rollback keeps the data together. Pause any
   listener or worker whose compatibility remains unproven.
3. For a checkpoint rollback, restore the matching pre-upgrade databases,
   Maildir, and configuration together into a separate directory. Review the
   messages, drafts, DAV changes, and send receipts accepted since that
   checkpoint before reopening intake. Use the saved current recovery point
   and the candidate binary to recover those writes, reconciling delivery
   receipts before retrying sends.
4. Verify healthy listeners, real inbound delivery, IMAP UID and UIDVALIDITY,
   a draft, and representative DAV resources before resuming the affected
   services. Keep both recovery points through the verification window.

### Preserve two-step verification during rollback

The current Mail database enforces two-step verification when a browser session
is created. During a binary-only rollback on that database, previously verified
sessions still work. A previous binary without the current verifier rejects new
sign-ins and Combined inbox links for enrolled mailboxes. Unenrolled webmail
and mail protocol access remain available. Restore the current binary to resume
interactive sign-in for enrolled mailboxes.

A database checkpoint may predate an enrollment or the consumption of a
recovery code. Run the restored daemon with `SMTP_ENABLE_WEBMAIL=false`. In
that temporary configuration, unset `SMTP_HOSTED_SIGN_IN_ORIGIN`,
`SMTP_WEBMAIL_MFA_KEY`, and `SMTP_WEBMAIL_OPERATOR_ID` if set. Keep a protected
copy of the normal configuration and key. Reconcile the current factor state
using the saved recovery point and the current verifier before reopening webmail.

Rehearse a binary-only rollback with a pre-MFA candidate that already supports
hosted sign-in and Combined inbox. The fixture enrolls a disposable mailbox,
checks all three session paths on the older binary, delivers SMTP mail and reads
it over IMAP, then rolls forward and spends a recovery code once.

```bash
python3 scripts/test-webmail-mfa.py /path/to/candidate --previous /path/to/previous-mail
```

### Rehearse a published-version rollback

Use the published executable for the version being replaced. Verify the
download against its release manifest and run this fixture on an isolated
host with throwaway accounts. The v0.3.26 rehearsal ran on Ubuntu 24.04 arm64.

```bash
python3 scripts/test-mail-release-upgrade.py /path/to/candidate --previous /path/to/released-mail
```

The fixture upgrades real mail, draft, and DAV data. For verified legacy DAV
collections, apply the [offline ownership assignment](../WEBMAIL.md#upgrading-persisted-dav-data).
Keep DAV paused when temporarily running v0.3.26 over a store that has those
assignments. Its mail worker is exercised against a simple compatible queued
send. The fixture then rolls the full store forward and checks the writes
from both versions, followed by a domain rename and a separate checkpoint
restore.

---

## Database Operations

### Backup Database

```bash
# Online backup (preferred)
sudo -u smtp sqlite3 /var/lib/mail/smtp.db ".backup /var/lib/mail/smtp-backup-$(date +%Y%m%d).db"

# Compress backup
sudo gzip /var/lib/mail/smtp-backup-*.db

# Copy to remote backup location
scp /var/lib/mail/smtp-backup-*.db.gz backup-server:/backups/smtp/
```

**Frequency:** Daily (automated via cron)

---

### Restore Database

```bash
# Stop service
sudo systemctl stop mail

# Restore backup
sudo -u smtp gunzip < /var/lib/mail/smtp-backup-20251024.db.gz > /var/lib/mail/smtp.db

# Verify integrity
sudo -u smtp sqlite3 /var/lib/mail/smtp.db "PRAGMA integrity_check;"

# Start service
sudo systemctl start mail
```

---

### Database Maintenance

```bash
# Vacuum database (monthly)
sudo -u smtp sqlite3 /var/lib/mail/smtp.db "VACUUM;"

# Update statistics
sudo -u smtp sqlite3 /var/lib/mail/smtp.db "ANALYZE;"

# Check integrity
sudo -u smtp sqlite3 /var/lib/mail/smtp.db "PRAGMA integrity_check;"

# Clean old queue entries
sudo -u smtp sqlite3 /var/lib/mail/smtp.db "DELETE FROM message_queue WHERE created_at < strftime('%s', 'now', '-30 days');"
```

---

## TLS Certificate Management

### Certificate Renewal (Let's Encrypt)

```bash
# Manual renewal (certbot handles auto-renewal)
sudo certbot renew

# Reload nginx after renewal
sudo systemctl reload nginx

# Verify certificate
openssl s_client -connect mail.example.com:25 -starttls smtp < /dev/null | grep "Verify return code"
# Expected: Verify return code: 0 (ok)
```

**Frequency:** Automatic (certbot timer runs twice daily)

---

### Certificate Monitoring

```bash
# Check expiry date
sudo certbot certificates

# Alert if < 30 days until expiry
EXPIRY=$(sudo openssl x509 -enddate -noout -in /etc/letsencrypt/live/mail.example.com/fullchain.pem | cut -d= -f2)
echo "Certificate expires: $EXPIRY"
```

---

## Backup and Restore

See the [authenticated Restic backup and recovery procedure](ENCRYPTION_AT_REST.md#backup-operations) for a full-service restore that includes Maildir and preserves verified message links.

### Full Backup Script

```bash
#!/bin/bash
# /opt/mail/scripts/backup.sh

BACKUP_DIR="/var/backups/mail"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RETENTION_DAYS=30

mkdir -p $BACKUP_DIR

# Backup database
sudo -u smtp sqlite3 /var/lib/mail/smtp.db ".backup $BACKUP_DIR/smtp-$TIMESTAMP.db"

# Backup configuration
sudo cp /etc/mail/config.env $BACKUP_DIR/config-$TIMESTAMP.env

# Compress
gzip $BACKUP_DIR/smtp-$TIMESTAMP.db

# Remove old backups
find $BACKUP_DIR -name "*.gz" -mtime +$RETENTION_DAYS -delete

# Verify latest backup
gunzip -t $BACKUP_DIR/smtp-$TIMESTAMP.db.gz && echo "Backup successful"

# Copy to remote location (optional)
# rsync -az $BACKUP_DIR/ backup-server:/backups/smtp/
```

**Setup:**
```bash
# Create cron job for daily backups at 2 AM
echo "0 2 * * * /opt/mail/scripts/backup.sh" | sudo crontab -
```

---

## Monitoring Setup

### Prometheus Configuration

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: 'mail'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:8081']
        labels:
          environment: 'production'
          service: 'mail'
```

### Grafana Dashboard

Import dashboard ID: (create custom dashboard with metrics from `/metrics`)

**Key Metrics to Monitor:**
- `smtp_connections_active` - Active connections
- `smtp_messages_received_total` - Message throughput
- `smtp_messages_rejected_total` - Rejection rate
- `smtp_auth_failures_total` - Authentication failures
- `smtp_rate_limit_hits_total` - Rate limiting

---

### Alerting Rules (Prometheus)

```yaml
# /etc/prometheus/rules/mail.yml
groups:
  - name: smtp_server_alerts
    interval: 30s
    rules:
      - alert: SMTPServerDown
        expr: up{job="mail"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Mail Server is down"
          description: "Mail Server {{ $labels.instance }} has been down for more than 1 minute"

      - alert: HighConnectionUsage
        expr: smtp_connections_active / smtp_max_connections > 0.8
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High connection usage"
          description: "Mail Server is using {{ $value }}% of max connections"

      - alert: HighRejectionRate
        expr: rate(smtp_messages_rejected_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High message rejection rate"
          description: "Rejection rate is {{ $value }} messages/sec"

      - alert: AuthenticationFailures
        expr: rate(smtp_auth_failures_total[5m]) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate"
          description: "Auth failure rate is {{ $value }} failures/sec (possible brute force attack)"
```

---

## Performance Tuning

### Connection Tuning

```bash
# For high-volume servers (5000+ messages/hour)
SMTP_MAX_CONNECTIONS=5000
SMTP_WORKER_THREADS=16
SMTP_DATABASE_POOL_SIZE=30
SMTP_BUFFER_POOL_SIZE=1000
```

### Kernel Tuning (Linux)

```bash
# /etc/sysctl.d/99-mail.conf
# Increase connection limits
net.core.somaxconn=4096
net.ipv4.tcp_max_syn_backlog=4096
net.ipv4.ip_local_port_range=10000 65535

# Enable TCP Fast Open
net.ipv4.tcp_fastopen=3

# Apply settings
sudo sysctl -p /etc/sysctl.d/99-mail.conf
```

---

## Incident Response

### Service Outage Response

1. **Detect:** Monitor alerts, health checks failing
2. **Assess:** Check service status, logs, metrics
3. **Communicate:** Notify stakeholders
4. **Investigate:** Review logs, metrics, recent changes
5. **Resolve:** Apply fix or rollback
6. **Verify:** Confirm service restoration
7. **Document:** Post-mortem report

### Common Issues and Solutions

**Issue: High Memory Usage**
```bash
# Check memory usage
ps aux | grep mail

# Restart service if OOM risk
sudo systemctl restart mail

# Adjust configuration
SMTP_MAX_CONNECTIONS=1000  # Reduce
SMTP_DATABASE_POOL_SIZE=10  # Reduce
```

**Issue: Database Locked**
```bash
# Check for long-running queries
sudo -u smtp sqlite3 /var/lib/mail/smtp.db "PRAGMA busy_timeout=10000;"

# Restart service
sudo systemctl restart mail
```

**Outbound queue and delivery alerts**

The watchdog checks free space on the runtime filesystem, the Maildir filesystem,
and the filesystem containing the configured `SMTP_DB_PATH`. It follows symlinks
and checks each filesystem once. It reports an unavailable path as a failed check.
The runtime defaults to `/opt/mail` and the Maildir to `/opt/mail/mail`. For a
different layout, set `--storage-path` and `--mailbox-path` when invoking
`mail-health-watch.py`. The runtime keeps a capacity check when the mailboxes and
database use a separate volume.

On hosts with the Mail health timer installed, the watchdog reads the SMTP
database configured by `SMTP_DB_PATH` in `/etc/mail/mail.env`. It raises an
incident when queued outbound deliveries in pending, processing, or retry
state exceed 1,000. A separate incident fires when terminal failures exceed
5% of completed outbound queue recipients in the current and previous 14 UTC
minute buckets. A recipient enters the denominator when the queue records
delivery or a terminal failure.

The watchdog sends incident and recovery notifications through its persisted
Discord outbox. A database read failure retains any active incident and
reports the monitoring failure. A slow notification receiver leaves SMTP
processing independent of alert delivery.

**Hosted operations and backup alerts**

Set `MAIL_OPERATIONS_TOKEN` in the Stacks app and add the same dedicated
credential to the root-managed Mail environment file. Set
`MAIL_APP_OPERATIONS_URL` there to the Stacks HTTPS origin followed by
`/api/operations/health`. The watchdog rejects redirects and stale reports.
The operator endpoint includes aggregate counts. Webmail health and alerts
use only fixed check labels and outcomes. The monitor retains active hosted
incidents while it cannot fetch a fresh report. After configuration has been
detected, removing the URL and token raises a hosted monitoring incident. A
disabled check also keeps an existing incident open. Restore the monitoring
configuration and confirm a fresh healthy result before treating it as recovered.

Hosted provisioning alerts on an unavailable private listener or a free or
paid mailbox still awaiting confirmation after 15 minutes. Billing alerts on
unprocessed signed webhook events older than 15 minutes, an absent or stale
reconciliation run, and mailbox access-update failures that persist for 15
minutes. Keep the Stacks billing scheduler running every five minutes.

When the Restic backup timer is installed, the watchdog checks the timestamp in
`/var/lib/mail-storage/data/restic/last-success`. A missing, invalid, future,
or more than 25-hour-old success marker opens an incident. Set
`MAIL_RESTIC_STATUS_FILE` in the Mail environment file when the configured
backup writes its success marker elsewhere. The marker is written after
Restic verifies the off-host backup.

**Scheduled backups on shared AWS staging**

Use the encrypted staging EBS volume for Mail data and backup working files.
Reserve a repository under `staging/backups/<name>` in a staging S3 bucket.
Grant the staging instance role bucket location and listing for that prefix,
and GetObject, PutObject, and DeleteObject on its objects. Use the instance
role for Restic authentication. Keep the repository password in a dedicated
staging recovery secret and install its copy as
`/etc/mail/staging-restic-password` (root-owned, mode 0600).

Set `RESTIC_REPOSITORY=s3:https://s3.<region>.amazonaws.com/<bucket>/staging/backups/<name>`
and `AWS_DEFAULT_REGION` in root-owned `/etc/mail/staging-restic.env` (mode 0600).
Install Restic and the SQLite CLI in the service PATH. Initialize the new
repository with `restic init` using the same repository, password file, and
instance role. Then run `sudo bash scripts/setup-staging-restic-backup.sh`
from a checkout or artifact that includes both backup scripts.

The timer runs shortly after installation and daily thereafter. The backup
reads the active Maildir and SQLite data, excludes the live environment file,
and verifies the remote packs before replacing
`/var/lib/mail-staging-backup/last-success`. Retention groups snapshots by
host and tag. Check the timer, service journal, and the watchdog's
`Verified off-host backup freshness` entry.

Restore a `mail-staging` snapshot into disposable storage using the staging
repository password. Extract the Mail archive, run `mail backup rebind-local`
on its SMTP database and Maildir, and verify SQLite and mailbox identities
before starting isolated listeners. Supply a separate test environment file.

To stop scheduling, run `systemctl disable --now mail-staging-restic.timer`
and `systemctl stop mail-staging-restic.service`. Remove the staging
`MAIL_RESTIC_STATUS_FILE` assignment from the Mail environment when retiring
the watchdog check. Retain the repository and its recovery password for the
staging retention window.

**Authenticated client sync alerts**

Create a dedicated mailbox, such as `sync-canary@staging.example.com`, and
leave its Inbox empty. Create the `Mail-Health` calendar and
`Mail-Health-Contacts` address book for that mailbox using authenticated
`MKCALENDAR` and `MKCOL` requests on `/calendars/<mailbox>/Mail-Health/` and
`/addressbooks/<mailbox>/Mail-Health-Contacts/`. Keep the canary separate from customer
mailboxes and routes.

Set `CALDAV_SYNC_CANARY_MAILBOX` in the Mail service environment to the
exact address of this already provisioned mailbox. The daemon resolves the
address at startup. On staging, verify the address and restart Mail first,
then enable the scheduled probe. The canary's calendar and address book
changes share a separate 16-entry history. Ordinary clients keep their
existing `CALDAV_MAX_SYNC_HISTORY` budget. The DAV token format stays the
same, including the usual fresh sync after a Mail restart.

Save the canary configuration to a root-owned file with mode 0600 and put its
path in `MAIL_SYNC_HEALTH_CONFIG` in the Mail environment file. Set its
`mailbox` to the same address.

```json
{
  "mailbox": "sync-canary@staging.example.com",
  "password": "<canary mailbox password>",
  "canary_id": "<32 lowercase hex characters from openssl rand -hex 16>",
  "imaps_port": 993,
  "dav_port": 443,
  "protocols": ["imap", "caldav", "carddav", "activesync", "ews"]
}
```

Set the ports to the actual local TLS listeners. A private CA can be
specified with `ca_file`. The monitor verifies the host certificate. It
appends one synthetic message over IMAPS, verifies its UID and reads the
new item using an ActiveSync SyncKey and EWS SyncState. The CalDAV and
CardDAV checks verify creation and deletion through successive sync
tokens. The monitor removes its own synthetic items and reports a failure
when the Inbox contains unrelated mail or a probe path holds unexpected
data. ActiveSync and EWS checks use IMAPS as the canary message writer.
The status report lists the selected protocols. If the canary configuration
is removed or omits a failing protocol, any existing incident stays open
until a fresh probe confirms recovery. Probe traffic, credentials and
returned item identifiers stay out of alerts.

The EWS canary starts with an empty Inbox and consumes the state from its
first item. Same-size replacement tracking is covered by
[the separate EWS sync issue](https://github.com/mail-os/mail/issues/133).

Run `python3 scripts/test-mail-sync-health.py /path/to/mail` for the
disposable native rehearsal. On staging, confirm a clean result with the
configured timer, induce a failure in the canary, and record the incident
and recovery at the staging receiver in #71.

```bash
systemctl status mail-health.timer
journalctl -u mail-health.service -n 30 --no-pager
sudo cat /var/lib/mail-health/public/status.json
```

---

## Maintenance Windows

### Scheduled Maintenance Template

**Pre-Maintenance (T-24 hours):**
- [ ] Notify users of maintenance window
- [ ] Complete full backup
- [ ] Test changes in staging
- [ ] Prepare rollback plan

**During Maintenance:**
- [ ] Set service to maintenance mode (reject with 421)
- [ ] Complete changes (upgrade, config, etc.)
- [ ] Validate changes
- [ ] Remove maintenance mode

**Post-Maintenance:**
- [ ] Monitor for 1 hour
- [ ] Notify users of completion
- [ ] Document changes

---

## See Also

- [Configuration Guide](./CONFIGURATION.md)
- [Troubleshooting Guide](./TROUBLESHOOTING.md)
- [API Reference](./API_REFERENCE.md)
- [Database Documentation](./DATABASE.md)

---

**Last Updated:** 2025-10-24
**Version:** v0.28.0
