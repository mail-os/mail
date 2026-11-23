# Client and automation decisions

These are the pilot decisions for [#78](https://github.com/mail-os/mail/issues/78).

## Installable web app

Offer Mail as a standalone window through browser installation. The inbox
is the launch page. The manifest and icons are embedded with the webmail
bundle and work on both hosted and self-hosted HTTPS origins. The install
instructions are in Account settings.

Installation uses the browser's confirmation and keeps the normal Mail
sign-in, linked-account boundaries, and separate notifications opt-in.
Reading mail requires an active connection to the server. The notification
worker handles notification clicks and leaves mail requests on the network.
The browser still opens Calendar, combined inboxes, and shared inboxes
inside the same app scope. Public snapshot and file-link pages retain their
own viewer experience. [Install Mail](../WEBMAIL.md#install-mail)

## Native clients

Use the existing SMTP submission and IMAP paths for mail and the DAV paths
for calendars and contacts. Keep the web app as the UI for Mail-specific
features including Sender Review, private collections, and Outbox review.
Collect pilot setup and sync failures before deciding whether to build a
first-party native client.

A native client authenticates to the mailbox that the owner configures.
Client credentials grant the protocol access documented for that account.
Operators configure the public HTTPS and TLS endpoints and publish only the
protocols they support. Product claims about specific clients require a
verified setup and sync journey. Hosted client credential lifecycle belongs
to [#58](https://github.com/mail-os/mail/issues/58). Migration through a
standard client belongs to [#54](https://github.com/mail-os/mail/issues/54).
[Mail client setup](IMAP_POP3.md#client-configuration)
· [Calendar and contacts setup](../WEBMAIL.md#calendar-and-contacts-clients)

## Terminal clients

Use the existing IMAP and submission routes for interactive terminal
clients. Cover reading a folder and submitting a message in the protocol
test suite. Gather a terminal-client setup problem from the pilot before
committing to a first-party terminal UI.

The mailbox owner supplies the credentials to their terminal client's
credential store. The Mail operator CLI retains its separate administration,
backup, and migration role. Terminal clients use the same mailbox limits
as other clients.

## Assistant automation

Build a separate mailbox-owner grant for two operations in the next slice.
An owner can approve reading selected messages and can separately approve
preparing drafts. The integration identity, selected messages, permissions,
and expiry must be visible before approval. The owner can revoke access
and review its audit history.

Drafts use the existing composer and its owner-controlled send action.
Browser sign-in, linked mailbox access, and hosted provisioning keep their
existing authorization contracts. [Scoped assistant grant](https://github.com/mail-os/mail/issues/120)

## Mail-to-web publishing

Defer publishing until the pilot identifies a use case that requires a
public page and its own audience. Use explicit, expiring snapshots for
sharing selected mail during the pilot.

If publishing proceeds, specify its grant separately. The owner needs an
exact content preview, a clear audience choice, and controls to withdraw the
page. Each publication needs an explicit decision about quoted mail,
attachments, indexing, and later replies.
[Snapshot and later reply sharing](https://github.com/mail-os/mail/issues/117)
