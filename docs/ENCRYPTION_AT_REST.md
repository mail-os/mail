# Encryption at rest

Production installs encrypt persisted mail data by default with a dedicated
LUKS2 filesystem on an independently attached Hetzner volume. The protected
paths include Maildirs, SQLite databases, DKIM material, forwarding rules,
local backups, certificate backups, Restic credentials, and the mail log.

The volume uses AES-XTS with a 512-bit key (two AES-256 keys, as required by
XTS). A cryptographically random volume key is generated during provisioning.
Initial installs wrap it with `systemd-creds` as the machine-bound encrypted
credential:

```text
/etc/credstore.encrypted/mail-storage-key.cred
```

The plaintext key exists only briefly in `/run` during initial provisioning.
`mail-storage.service` receives it as a private runtime credential, unlocks the
volume, and mounts it at `/var/lib/mail-storage` before `mail.service` starts.
The unprivileged mail process can access the mounted data but cannot read the
persistent key credential.

The server retains its established paths under `/opt/mail`; those paths point
into the encrypted mount so SMTP, IMAP, POP3, CalDAV, CLI tools, and backups all
see the same data layout.

## Verification

```bash
systemctl is-active mail-storage mail
findmnt /var/lib/mail-storage
cryptsetup status mail-storage
systemd-creds decrypt --name=mail-storage-key \
  /etc/credstore.encrypted/mail-storage-key.cred - >/dev/null
```

## Object storage

Cloud deployments apply a customer-managed KMS key with automatic rotation to
private email and backup buckets. This is separate from LUKS2 and Restic: LUKS
protects live host data, Restic encrypts and authenticates backup content
before upload, and KMS-backed bucket encryption adds provider-side protection.

Create or reconcile the KMS key and bucket policies:

```bash
buddy mail:storage:kms:ensure --profile stacks
```

## External key mode

Hetzner VMs currently expose no TPM. For protection against theft of the entire
root disk, production can externalize the LUKS key into AWS Secrets Manager,
where it is encrypted by AWS KMS:

```bash
buddy mail:storage:externalize --profile stacks
```

External mode removes the mail volume credential from the host. After a reboot,
mail remains stopped until an authorized workstation streams the key from
Secrets Manager directly into `cryptsetup`:

```bash
buddy mail:storage:status
buddy mail:storage:key:verify --profile stacks
buddy mail:storage:unlock --profile stacks
buddy mail:storage:lock
```

The key is never placed in a command-line argument, environment variable, log,
or persistent file on the mail host. `mail:storage:unlock` holds it in the
operator process briefly and sends it over SSH stdin.

An independent recovery key can be added to a second LUKS2 keyslot and stored
in the operator's macOS Keychain:

```bash
buddy mail:storage:key:recovery:add --profile stacks
buddy mail:storage:key:recovery:verify
```

The command streams both keys over SSH stdin, verifies the new keyslot, writes
the recovery key to Keychain without placing it in argv, reads it back, and
tests it against the LUKS header. If a failed enrollment leaves an unwanted
keyslot, inspect the LUKS header and remove only the explicitly selected slot:

```bash
buddy mail:storage:key:slot:remove --slot <number> --profile stacks
```

The removal command refuses the primary slot and requires the remaining
external key to unlock the volume, so it cannot silently remove the last
usable credential.

## Dedicated volume

Move an existing root-disk LUKS image to a separately attached Hetzner volume:

```bash
buddy mail:storage:volume:migrate --size 20 --profile stacks
```

The operation creates or reuses `stacks-production-mail`, stops mail, performs
a byte-verified sparse copy, preserves the LUKS UUID and keyslots, unlocks with
the externally stored key, grows the encrypted filesystem, validates the
service, and only then removes the root-disk rollback image. A failed
validation automatically restores the original image.

## Recovery

Before externalization, the encrypted credential is bound to the machine's
systemd host secret. A machine-image or disaster-recovery backup must retain
both:

```text
/etc/credstore.encrypted/mail-storage-key.cred
/var/lib/systemd/credential.secret
```

After `mail:storage:externalize`, neither file is sufficient to unlock the mail
volume because the local credential has been removed. Recovery then uses the
AWS Secrets Manager entry (by default
`stacks/production/mail-storage-key`):

```bash
buddy mail:storage:key:verify --profile stacks
buddy mail:storage:unlock --profile stacks
```

Back up the LUKS header separately after provisioning or changing key slots.
The Buddy command streams it to S3 and requests KMS encryption without leaving
a persistent local copy:

```bash
buddy mail:storage:header:backup --profile stacks
```

The header backup is not a volume key, but it is sensitive and must be kept in
encrypted offline storage. Losing every valid external key or destroying the
LUKS header makes the volume unrecoverable by design.

## Backup operations

Local backups are created inside the encrypted filesystem, use SQLite's online
backup API, and verify the archive before publishing it:

```bash
buddy mail:storage:backup
systemctl status mail-backup.timer
```

Cloud object storage encryption is provider-side and independent from LUKS.
Keep bucket default encryption enabled even when uploaded archives came from
the encrypted host volume.

Authenticated off-host backups use Restic with a dedicated least-privilege IAM
user. The Restic password and AWS credentials are stored both inside the
unlocked encrypted filesystem for unattended backups and in the
KMS-encrypted `stacks/production/mail-restic` recovery secret.

```bash
buddy mail:storage:restic:configure --profile stacks
buddy mail:storage:restore:check --profile stacks
```

The daily job creates a verified SQLite-consistent local snapshot, uploads it
through Restic, applies 7 daily / 5 weekly / 12 monthly retention, prunes,
and performs a repository data check. The restore check downloads the newest
snapshot to a temporary directory on the encrypted filesystem, validates both
archives, runs SQLite `quick_check`, and confirms that mail and forwarding data
are present. An hourly health timer fails when the encrypted mount is missing,
usage crosses configured thresholds, or the newest successful off-host backup
is stale.

## Recovery order

1. Attach and mount the Hetzner data volume.
2. Retrieve either the AWS secret or independent Keychain recovery key.
3. Unlock `/var/lib/mail-storage.luks`.
4. Start `mail.service` and validate SQLite plus Maildir counts.
5. If the volume is unavailable, restore the latest Restic snapshot and its
   environment archive onto a newly encrypted volume.

Implementation and operational follow-up are tracked in
[mail-os/mail#4](https://github.com/mail-os/mail/issues/4).
