#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mail_env=/etc/mail/mail.env
backup_config=/etc/mail/staging-restic.env
password=/etc/mail/staging-restic-password
status=/var/lib/mail-staging-backup/last-success
target=/opt/mail/maintenance/staging-backup

die() {
  echo "setup-staging-restic-backup: $*" >&2
  exit 1
}

[[ $EUID -eq 0 ]] || die "must run as root"
grep -Fxq 'SMTP_PROFILE=staging' "$mail_env" || die "requires a staging Mail instance"
for file in "$backup_config" "$password"; do
  [[ -f "$file" && ! -L "$file" && "$(stat -c '%u:%a' "$file")" == '0:600' && -s "$file" ]] \
    || die "expected a root-owned mode 0600 file at $file"
done
command -v restic >/dev/null && command -v sqlite3 >/dev/null || die "install Restic and the SQLite CLI"
[[ -x /opt/mail/mail-server && -f /var/lib/mail/smtp.db && -d /var/lib/mail/mail ]] \
  || die "expected the shared staging Mail installation"

install -d -m 0700 "$target"
install -m 0700 "$script_dir/mail-backup.sh" "$script_dir/mail-staging-restic-backup.sh" "$target"

cat > /etc/systemd/system/mail-staging-restic.service <<'UNIT'
[Unit]
Description=Encrypted off-host Mail backup for staging
After=network-online.target mail.service
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=/etc/mail/staging-restic.env
LoadCredential=restic-password:/etc/mail/staging-restic-password
StateDirectory=mail-staging-backup
StateDirectoryMode=0700
ExecStart=/opt/mail/maintenance/staging-backup/mail-staging-restic-backup.sh /var/lib/mail /etc/mail/mail.env /opt/mail/mail-server
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
TimeoutStartSec=15min
UNIT

cat > /etc/systemd/system/mail-staging-restic.timer <<'UNIT'
[Unit]
Description=Daily encrypted Mail backup for staging

[Timer]
OnActiveSec=30s
OnCalendar=*-*-* 03:20:00 UTC
Persistent=true
AccuracySec=1s

[Install]
WantedBy=timers.target
UNIT

# The running watchdog reads this setting from the same root-managed file.
exec 9>/run/mail-health-check.lock
flock -w 220 9
if grep -q '^MAIL_RESTIC_STATUS_FILE=' "$mail_env"; then
  grep -Fxq "MAIL_RESTIC_STATUS_FILE=$status" "$mail_env" || die "a different backup freshness receipt is configured"
else
  staged=$(mktemp /etc/mail/.staging-restic-env.XXXXXXXX)
  trap 'rm -f -- "$staged"' EXIT
  cp --preserve=all "$mail_env" "$staged"
  printf '\nMAIL_RESTIC_STATUS_FILE=%s\n' "$status" >> "$staged"
  mv -fT "$staged" "$mail_env"
fi
flock -u 9

systemctl daemon-reload
systemctl enable --now mail-staging-restic.timer
