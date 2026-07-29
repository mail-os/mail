#!/usr/bin/env bash
# Mail server host provisioning (idempotent). Baked into the repo so every
# deployment gets the same operational hardening: fail2ban brute-force
# protection + daily backups of mailboxes, databases, DKIM key and config.
#
# Run as root on the mail host:  bash hetzner-provision.sh
set -euo pipefail

MAIL_DIR="${MAIL_DIR:-/opt/mail}"
BACKUP_DIR="${BACKUP_DIR:-/opt/mail/backups}"
RETAIN_DAYS="${RETAIN_DAYS:-7}"
SWAP_GB="${SWAP_GB:-2}"
FAIL2BAN_IGNORE_IPS="${FAIL2BAN_IGNORE_IPS:-127.0.0.1/8 ::1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

echo "== memory safety =="
# The production box is shared with Bun applications. Give short deployment
# spikes somewhere safe to go instead of letting the global OOM killer choose
# the mail daemon. This is idempotent and intentionally low-swappiness.
if [ "$SWAP_GB" -gt 0 ] && ! swapon --show=NAME --noheadings 2>/dev/null | grep -qx '/swapfile'; then
  if [ ! -f /swapfile ]; then
    fallocate -l "${SWAP_GB}G" /swapfile || dd if=/dev/zero of=/swapfile bs=1M count="$((SWAP_GB * 1024))" status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
  fi
  swapon /swapfile
fi
if [ "$SWAP_GB" -gt 0 ]; then
  grep -qE '^/swapfile\s' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  echo 'vm.swappiness=10' > /etc/sysctl.d/99-mail-swap.conf
  sysctl -w vm.swappiness=10 >/dev/null
fi

# Protect the small, stable mail process when unrelated co-tenants consume the
# host. MemoryLow reserves reclaim protection; OOMScoreAdjust makes mail a last
# resort without making it unkillable if it is ever genuinely at fault.
mkdir -p /etc/systemd/system/mail.service.d
cat > /etc/systemd/system/mail.service.d/resources.conf <<'UNIT'
[Service]
MemoryAccounting=true
MemoryLow=128M
OOMScoreAdjust=-750
Restart=always
RestartSec=3
UNIT
systemctl daemon-reload

echo "== fail2ban =="
if ! command -v fail2ban-server >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq fail2ban >/dev/null
fi
# sshd and mail authentication jails. The mail daemon emits one stable,
# credential-free failure line for every supported SMTP and IMAP mechanism.
cat > /etc/fail2ban/filter.d/mail-auth.conf <<'FILTER'
[Definition]
failregex = ^.*Failed (?:IMAP|SMTP) authentication from <HOST>.*$
ignoreregex =
journalmatch = _SYSTEMD_UNIT=mail.service
FILTER

cat > /etc/fail2ban/jail.local <<JAIL
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd
ignoreip = $FAIL2BAN_IGNORE_IPS

[sshd]
enabled = true

[mail-auth]
enabled = true
filter = mail-auth
port = smtp,submission,submissions,imap,imaps
maxretry = 5
JAIL
systemctl enable --now fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban || true
echo "fail2ban: $(systemctl is-active fail2ban)"

echo "== encrypted storage =="
if ! command -v cryptsetup >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq cryptsetup >/dev/null
fi
chmod +x "${REPO_ROOT}/scripts/setup-encrypted-storage.sh"
MAIL_ROOT="${MAIL_DIR}" "${REPO_ROOT}/scripts/setup-encrypted-storage.sh"

echo "== backups =="
mkdir -p "$BACKUP_DIR"
install -m 0755 "${REPO_ROOT}/scripts/mail-backup.sh" "$MAIL_DIR/backup.sh"
install -m 0755 "${REPO_ROOT}/scripts/mail-forward-compile" /usr/local/sbin/mail-forward-compile
install -m 0755 "${REPO_ROOT}/scripts/maildir-migrate.sh" /usr/local/sbin/maildir-migrate

cat > /etc/systemd/system/mail-backup.service <<'U'
[Unit]
Description=Mail server backup
Requires=mail-storage.service
After=mail-storage.service
[Service]
Type=oneshot
ExecStart=/opt/mail/backup.sh
U
cat > /etc/systemd/system/mail-backup.timer <<'U'
[Unit]
Description=Daily mail server backup
[Timer]
OnCalendar=*-*-* 02:30:00
RandomizedDelaySec=900
Persistent=true
[Install]
WantedBy=timers.target
U
systemctl daemon-reload
systemctl enable --now mail-backup.timer >/dev/null 2>&1 || true
echo "backup timer: $(systemctl is-active mail-backup.timer)"

# run one backup now to validate
"$MAIL_DIR/backup.sh"
echo "== provisioning complete =="
