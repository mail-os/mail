#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESTIC_CONFIG_DIR="${MAIL_RESTIC_CONFIG_DIR:-/var/lib/mail-storage/data/restic}"

[[ "${EUID}" -eq 0 ]] || {
  echo "setup-restic-backup: must run as root" >&2
  exit 1
}
mountpoint -q /var/lib/mail-storage || {
  echo "setup-restic-backup: encrypted mail storage is not mounted" >&2
  exit 1
}

if ! command -v restic >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq restic
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y restic
  else
    echo "setup-restic-backup: unsupported package manager" >&2
    exit 1
  fi
fi

install -d -m 0700 -o root -g root "${RESTIC_CONFIG_DIR}"
install -m 0755 "${SCRIPT_DIR}/mail-restic-backup.sh" /usr/local/sbin/mail-restic-backup
install -m 0755 "${SCRIPT_DIR}/mail-restic-restore-check.sh" /usr/local/sbin/mail-restic-restore-check
install -m 0755 "${SCRIPT_DIR}/mail-storage-health.sh" /usr/local/sbin/mail-storage-health
install -m 0755 "${SCRIPT_DIR}/maildir-migrate.sh" /usr/local/sbin/maildir-migrate
install -m 0755 "${SCRIPT_DIR}/mail-forward-compile" /usr/local/sbin/mail-forward-compile

cat > /etc/systemd/system/mail-restic-backup.service <<'UNIT'
[Unit]
Description=Authenticated off-host mail backup
After=network-online.target mail-storage.service
Wants=network-online.target
ConditionPathIsMountPoint=/var/lib/mail-storage

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/mail-restic-backup
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/mail-storage /opt/mail
UNIT

cat > /etc/systemd/system/mail-restic-backup.timer <<'UNIT'
[Unit]
Description=Daily authenticated off-host mail backup

[Timer]
OnCalendar=*-*-* 03:20:00 UTC
Persistent=true
RandomizedDelaySec=15m

[Install]
WantedBy=timers.target
UNIT

cat > /etc/systemd/system/mail-storage-health.service <<'UNIT'
[Unit]
Description=Mail storage capacity and backup freshness check
After=mail-storage.service
ConditionPathIsMountPoint=/var/lib/mail-storage

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/mail-storage-health
UNIT

cat > /etc/systemd/system/mail-storage-health.timer <<'UNIT'
[Unit]
Description=Hourly mail storage health check

[Timer]
OnBootSec=10m
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable mail-restic-backup.timer mail-storage-health.timer >/dev/null
echo "setup-restic-backup: installed"
