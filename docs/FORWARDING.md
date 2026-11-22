# Forwarding

## Mailbox forwarding

In webmail, open **Account → Forwarding**. Enter the destination and your
current password, then enter the code from the destination inbox. The code
expires after 30 minutes and works once. A replacement takes effect when its
address is verified. **Cancel request** clears a pending verification.
**Turn off forwarding** stops forwarding mail accepted after that change.
Copies already accepted by the delivery queue keep the recipient they had
when the server accepted the mail.

Mailbox forwarding always keeps the local original. Junk, held or declined
senders, delivery-status messages, automated notices, and already forwarded
copies are excluded. Approving a held copy can release it for forwarding.
Local destinations are tied to the verified mailbox identity. External
copies use the source mailbox's domain and attach the original as an `.eml`
file. External forwarding uses the source mailbox's hosted daily sending
allowance and the relay's message-size limit.

## Administrator-managed forwarding

Forwarding is declared in each Stacks application's `config/email.ts`:

```ts
forwards: {
  'socials@stacksjs.com': ['chris@stacksjs.com'],
  'hi@stacksjs.com': ['chris@stacksjs.com'],
}
```

Buddy merges those declarations into the shared `/opt/mail/forwards.json`
manifest and atomically compiles `/opt/mail/forwards.sieve`. The runtime script
uses the standard RFC 5228 Sieve `envelope`, `redirect`, and `keep` commands.
The JSON file is retained as a generated compatibility manifest for older
server binaries; it is not the configuration source.

Example generated rule:

```sieve
require ["envelope"];

if envelope :is "to" "socials@stacksjs.com" {
    redirect "chris@stacksjs.com";
    keep;
}
```

Rules are loaded for each accepted non-junk message. `keep` leaves the original
copy in the role mailbox, while `redirect` creates the forwarded copy. Junk is
not forwarded, which prevents the server from relaying spam.

SMTP DATA, SMTP BDAT, and app-originated local mail use the same routing plan.
The server records acceptance and reserves hosted storage before it replies.
Each local copy is checkpointed independently, so a restart can finish pending
copies without re-delivering those already filed. A redirect starts after its
primary copy is committed. A full or disabled forwarding destination leaves the
original delivery intact. Remote SMTP deliveries enter the existing retry queue
in the acceptance transaction. `SMTP_DB_PATH` holds the acceptance journal on
SMTP-only installations as well as servers with authentication and webmail.

When a mailbox has Sender Review enabled, a sender's approval applies only
to a verified author. Authenticated app and SMTP submissions establish the
author through the authenticated identity. Inbound mail needs a DMARC pass for
the parsed author. Approved mail follows the normal forwarding rules unless the
sender's rule disables forwarding. Pending and declined mail stays available
for review without forwarding or triggering Inbox notifications.

Approving a held message releases it and applies forwarding once. An approval
for an unverified copy applies to that copy. Recovering a single declined
message restores it to the inbox and keeps the sender's future disposition.

Reconcile from configuration and validate the live script:

```bash
buddy mail:provision --env production
buddy mail:forward:compile
```

The compiler rejects invalid mailbox names, invalid destination addresses,
empty target lists, and control characters. It sorts rules and removes
duplicate targets for deterministic output.

Implementation follow-up is tracked in
[mail-os/mail#6](https://github.com/mail-os/mail/issues/6).
