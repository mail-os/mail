#!/bin/sh
# Installs protocol monitoring independently of deployment-generated wrappers.
set -eu
source_file="${1:?usage: setup-mail-health.sh /path/to/mail-health.py}"
source_dir="$(dirname "$source_file")"
install -d -m 0700 /opt/mail/maintenance
install -m 0700 "$source_file" /opt/mail/maintenance/mail-health.py
install -m 0700 "$source_dir/mail-health-watch.py" /opt/mail/maintenance/mail-health-watch.py
install -d -m 0750 -o root -g mail-server /var/lib/mail-health /var/lib/mail-health/public
install -d -m 0700 /var/lib/mail-health/private
# Future atomic snapshots inherit the public directory's mail-server group.
chmod g+s /var/lib/mail-health/public
# Never rotate on deployment: only the daemon and root can read this credential.
if [ ! -s /var/lib/mail-health/public/read-token ]; then
  umask 077
  python3 -c 'import secrets; print(secrets.token_hex(32), end="")' > /var/lib/mail-health/public/read-token
fi
chown root:mail-server /var/lib/mail-health/public/read-token
chmod 0640 /var/lib/mail-health/public/read-token
cat > /usr/local/sbin/mail-protocol-health-check <<'CHECK'
#!/bin/sh
set -eu
exec 9>/run/mail-health-check.lock
flock -n 9 || exit 0
# Try existing listener recovery once, but always publish/report health even if
# recovery fails. No protocol failure is hidden by restarting the daemon.
needs_restart=0
systemctl is-active --quiet mail || needs_restart=1
for port in 25 143 465 587 993; do
  ss -H -ltn "sport = :$port" | grep -q . || needs_restart=1
done
if [ "$needs_restart" = 1 ]; then
  logger -t mail-health 'Mail inactive or missing a listener; attempting recovery'
  systemctl restart mail || logger -t mail-health 'Mail restart failed'
  sleep 2
fi
mail_hostname="$(sed -n 's/^SMTP_HOSTNAME=//p' /etc/mail/mail.env | head -1)"
exec python3 /opt/mail/maintenance/mail-health-watch.py --host "${mail_hostname:-mail.stacksjs.com}"
CHECK
chmod 0755 /usr/local/sbin/mail-protocol-health-check
cat > /usr/local/sbin/mail-health-check <<'CHECK'
#!/bin/sh
exec /usr/local/sbin/mail-protocol-health-check
CHECK
chmod 0755 /usr/local/sbin/mail-health-check
cat > /etc/systemd/system/mail-health.service <<'UNIT'
[Unit]
Description=Verify mail protocols, delivery errors and admin alerts
After=mail.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/mail-health-check
TimeoutStartSec=150
UNIT
# Older tenant tools can rewrite the base unit and legacy wrapper. A drop-in
# keeps the release's protocol monitor authoritative across those deploys.
install -d -m 0755 /etc/systemd/system/mail-health.service.d
cat > /etc/systemd/system/mail-health.service.d/protocol.conf <<'UNIT'
[Service]
ExecStart=
ExecStart=/usr/local/sbin/mail-protocol-health-check
TimeoutStartSec=150
UNIT
cat > /etc/systemd/system/mail-health.timer <<'UNIT'
[Unit]
Description=Verify mail delivery health every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s
Persistent=true

[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now mail-health.timer
