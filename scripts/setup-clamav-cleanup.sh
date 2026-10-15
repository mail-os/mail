#!/usr/bin/env bash
# A separate unit keeps this rule independent of tenant deploys, which replace
# the shared ts-cloud cleanup policy on every deployment.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ "${EUID}" -eq 0 ]] || { echo 'setup-clamav-cleanup: must run as root' >&2; exit 1; }
install -m 0755 "${SCRIPT_DIR}/cleanup-clamav-downloads.sh" /usr/local/sbin/mail-clamav-temp-cleanup

cat > /etc/systemd/system/mail-clamav-temp-cleanup.service <<'UNIT'
[Unit]
Description=Remove abandoned ClamAV signature downloads

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/mail-clamav-temp-cleanup
Nice=19
IOSchedulingClass=idle
UNIT

cat > /etc/systemd/system/mail-clamav-temp-cleanup.timer <<'UNIT'
[Unit]
Description=Hourly cleanup of abandoned ClamAV signature downloads

[Timer]
OnBootSec=10m
OnUnitActiveSec=1h
RandomizedDelaySec=5m

[Install]
WantedBy=timers.target
UNIT

systemctl daemon-reload
systemctl enable --now mail-clamav-temp-cleanup.timer
