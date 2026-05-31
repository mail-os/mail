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

echo "== fail2ban =="
if ! command -v fail2ban-server >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq fail2ban >/dev/null
fi
# sshd jail (the main brute-force vector). A mail-auth jail can be added once
# the server's failed-AUTH log line format is finalized.
cat > /etc/fail2ban/jail.local <<'JAIL'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd

[sshd]
enabled = true
JAIL
systemctl enable --now fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban || true
echo "fail2ban: $(systemctl is-active fail2ban)"

echo "== backups =="
mkdir -p "$BACKUP_DIR"
cat > "$MAIL_DIR/backup.sh" <<BK
#!/usr/bin/env bash
set -euo pipefail
TS=\$(date +%Y%m%d-%H%M%S)
OUT="$BACKUP_DIR/mail-backup-\$TS.tgz"
# mailboxes + databases + DKIM key + config (exclude the backups dir itself)
tar czf "\$OUT" \\
  -C "$MAIL_DIR" mail smtp.db caldav.db dkim 2>/dev/null || true
[ -f /etc/mail/mail.env ] && tar rf "\${OUT%.tgz}.env.tar" -C /etc/mail mail.env 2>/dev/null || true
# prune old backups
find "$BACKUP_DIR" -name 'mail-backup-*.tgz' -mtime +$RETAIN_DAYS -delete 2>/dev/null || true
echo "backup written: \$OUT (\$(du -h "\$OUT" 2>/dev/null | cut -f1))"
BK
chmod +x "$MAIL_DIR/backup.sh"

cat > /etc/systemd/system/mail-backup.service <<'U'
[Unit]
Description=Mail server backup
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
