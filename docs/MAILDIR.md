# Maildir++ storage

Production mailboxes use Maildir++:

```text
mail/<mailbox>/
├── tmp/
├── new/
├── cur/
├── .Junk/
│   ├── tmp/
│   ├── new/
│   └── cur/
└── Junk -> .Junk/cur
```

The dot-prefixed directory is the standard Maildir++ representation. The
visible relative symlink is a compatibility bridge for older server paths and
is included in IMAP LIST responses. New IMAP folders are created in this form.
DELETE and RENAME update the canonical directory and compatibility link
together.

Migrate an existing server with the reusable Buddy operation:

```bash
buddy mail:storage:maildir:migrate
```

The migration stops `mail.service`, creates missing `tmp/new/cur` directories,
moves existing flat-folder messages to `.Folder/cur`, installs relative
compatibility symlinks, and restarts the service. It is idempotent and refuses
unexpected symlink targets, filename collisions, and nested legacy folders.

Direct server invocation:

```bash
/usr/local/sbin/maildir-migrate status
/usr/local/sbin/maildir-migrate migrate
```

Backups archive one copy of each folder rather than dereferencing both the
canonical directory and its compatibility link.

Implementation follow-up is tracked in
[mail-os/mail#5](https://github.com/mail-os/mail/issues/5).
