#!/usr/bin/env bash
# Install the embedded UI behind the shared rpx HTTPS gateway. No second app service.
set -euo pipefail
TARGET="${1:?usage: deploy-webmail.sh root@HOST}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scp "$REPO_ROOT/scripts/renew-webmail-cert.sh" "$TARGET:/tmp/renew-webmail-cert.sh"
scp "$REPO_ROOT/packages/cloud/webmail.gateway.json" "$TARGET:/tmp/mail-webmail.gateway.json"
ssh "$TARGET" 'bash -s' <<'REMOTE'
set -euo pipefail
test -d /etc/rpx/sites.d
test -f /etc/rpx/gateway.ts
# Keep SMTP/IMAP TLS enabled; only the loopback webmail listener uses gateway TLS.
cp -a /etc/mail/mail.env /etc/mail/mail.env.bak-webmail
python3 - <<'PYREMOTE'
from pathlib import Path
p = Path('/etc/mail/mail.env')
settings = {'SMTP_ENABLE_WEBMAIL': 'true', 'SMTP_WEBMAIL_PORT': '8099', 'SMTP_WEBMAIL_TLS': 'false', 'SMTP_WEBMAIL_SECURE_COOKIES': 'true'}
lines = [line for line in p.read_text().splitlines() if line.split('=', 1)[0] not in settings]
p.write_text('\n'.join(lines + [key + '=' + value for key, value in settings.items()]) + '\n')
PYREMOTE
install -m 644 /tmp/mail-webmail.gateway.json /etc/rpx/sites.d/mail.json.new
mv /etc/rpx/sites.d/mail.json.new /etc/rpx/sites.d/mail.json
systemctl restart mail.service
sleep 3
systemctl is-active --quiet mail.service
curl --fail --silent http://127.0.0.1:8099/login >/dev/null
systemctl restart rpx-gateway.service
sleep 3
systemctl is-active --quiet rpx-gateway.service
# Public certificates must exist before the first HTTPS request. rpx's
# on-demand issuer starts on plaintext HTTP, not during the TLS handshake.
install -m 755 /tmp/renew-webmail-cert.sh /etc/rpx/renew-certs-mail.sh
cat > /etc/systemd/system/rpx-cert-renew-mail.service <<'UNIT'
[Unit]
Description=Provision and renew the mail UI TLS certificate
After=network-online.target rpx-gateway.service
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/etc/rpx/renew-certs-mail.sh
UNIT
cat > /etc/systemd/system/rpx-cert-renew-mail.timer <<'UNIT'
[Unit]
Description=Renew the mail UI certificate daily
[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now rpx-cert-renew-mail.timer
systemctl start rpx-cert-renew-mail.service
curl --fail --silent --retry 5 --retry-delay 3 https://mail.stacksjs.com/login >/dev/null
REMOTE
