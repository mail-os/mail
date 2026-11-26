set -Eeuo pipefail
umask 077

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y certbot clamav-daemon clamav-freshclam curl dnsutils nodejs openssl python3 unzip

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

# Ubuntu Noble has no awscli apt candidate. Use the official AWS CLI v2 installer.
if ! command -v aws >/dev/null 2>&1; then
  curl --fail --silent --show-error --location --retry 3 \
    https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o "$workdir/awscli.zip"
  unzip -q "$workdir/awscli.zip" -d "$workdir"
  "$workdir/aws/install"
fi

# The published bundle is specific to the candidate, including the health scripts.
export AWS_DEFAULT_REGION="$region"
export AWS_MAX_ATTEMPTS=10
aws s3 cp "$artifact" "$workdir/mail.tar.gz" --only-show-errors
printf '%s  %s\n' "$artifact_sha" "$workdir/mail.tar.gz" | sha256sum -c -
for file in mail-server mail-health.py mail-health-watch.py mail-sync-health.py setup-mail-health.sh; do
  tar -xOzf "$workdir/mail.tar.gz" "$file" > "$workdir/$file"
  test -s "$workdir/$file"
done

if ! id mail-server >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /opt/mail --shell /usr/sbin/nologin mail-server
fi
install -d -m 0750 -o root -g mail-server /etc/mail
install -d -m 0755 -o root -g root /opt/mail
install -d -m 0750 -o mail-server -g mail-server /var/lib/mail /var/lib/mail/mail
ln -sTfn /var/lib/mail/mail /opt/mail/mail
install -m 0755 -o root -g root "$workdir/mail-server" /opt/mail/mail-server

# Keep the staging scanner private and limit memory during signature reloads.
systemctl stop clamav-daemon.service clamav-daemon.socket
sed -i -E '/^(LocalSocketMode|ConcurrentDatabaseReload|SelfCheck) /d' /etc/clamav/clamd.conf
printf '%s\n' 'LocalSocketMode 660' 'ConcurrentDatabaseReload false' 'SelfCheck 600' >> /etc/clamav/clamd.conf
# The scanner watches its signature files without enabling the socket's RELOAD command.
sed -i -E '/^NotifyClamd /d' /etc/clamav/freshclam.conf
systemctl daemon-reload
systemctl enable clamav-freshclam.service
systemctl restart clamav-freshclam.service
for attempt in $(seq 1 60); do
  if { [ -s /var/lib/clamav/main.cvd ] || [ -s /var/lib/clamav/main.cld ]; } &&
     { [ -s /var/lib/clamav/daily.cvd ] || [ -s /var/lib/clamav/daily.cld ]; }; then
    break
  fi
  if [ "$attempt" -eq 60 ]; then
    echo 'ClamAV signature databases did not become ready' >&2
    exit 1
  fi
  sleep 3
done
systemctl enable --now clamav-daemon.service
runuser -u mail-server -g mail-server -G clamav -- python3 - <<'CLAMD'
import socket
import time

for _ in range(90):
    try:
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(2)
            client.connect("/run/clamav/clamd.ctl")
            client.sendall(b"zPING\0")
            if client.recv(128).rstrip(b"\0\n") == b"PONG":
                break
    except OSError:
        pass
    time.sleep(1)
else:
    raise SystemExit("The Mail service account cannot reach ClamAV")
CLAMD

# Wait for CloudFormation's A record and use a certificate trusted by test clients.
for attempt in $(seq 1 18); do
  if dig +short +time=2 +tries=1 "$hostname" A | grep -qE '^[0-9.]+$' &&
      certbot certonly --standalone --non-interactive --agree-tos --keep-until-expiring \
        --email "admin@$mail_domain" -d "$hostname"; then
    break
  fi
  if [ "$attempt" -eq 18 ]; then
    echo "Could not obtain a certificate for $hostname" >&2
    exit 1
  fi
  sleep 15
done

install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/mail <<'HOOK'
#!/bin/bash
set -euo pipefail
install -m 0640 -o root -g mail-server "$RENEWED_LINEAGE/fullchain.pem" /etc/mail/fullchain.pem
install -m 0640 -o root -g mail-server "$RENEWED_LINEAGE/privkey.pem" /etc/mail/privkey.pem
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/mail
RENEWED_LINEAGE="/etc/letsencrypt/live/$hostname" /etc/letsencrypt/renewal-hooks/deploy/mail
install -d -m 0755 /etc/letsencrypt/renewal-hooks/{pre,post}
printf '#!/bin/sh\nsystemctl stop mail\n' > /etc/letsencrypt/renewal-hooks/pre/mail
printf '#!/bin/sh\nsystemctl start mail\n' > /etc/letsencrypt/renewal-hooks/post/mail
chmod 0755 /etc/letsencrypt/renewal-hooks/{pre,post}/mail

# The daemon binds the provisioning listener to loopback.
parameter() {
  aws ssm get-parameter --with-decryption --name "/mail-server/staging/$1" --query Parameter.Value --output text
}
provisioning_token=$(parameter provisioning-token)
if [[ ! "$provisioning_token" =~ ^[0-9a-fA-F]{64}$ ]]; then
  echo 'The staging provisioning token must be 32 hex-encoded bytes' >&2
  exit 1
fi
discord_webhook=$(parameter discord-webhook-url 2>/dev/null || true)
if [ -n "$discord_webhook" ] && [[ ! "$discord_webhook" =~ ^https://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+$ ]]; then
  echo 'Invalid staging Discord webhook URL' >&2
  exit 1
fi

cat > /etc/mail/mail.env <<ENV
SMTP_PROFILE=staging
SMTP_HOST=0.0.0.0
SMTP_PORT=25
SMTP_HOSTNAME=$hostname
SMTP_LOCAL_DOMAINS=$mail_domain
SMTP_DB_PATH=/var/lib/mail/smtp.db
SMTP_ENABLE_AUTH=true
SMTP_REQUIRE_TLS_FOR_AUTH=true
SMTP_ENABLE_TLS=true
SMTP_TLS_CERT=/etc/mail/fullchain.pem
SMTP_TLS_KEY=/etc/mail/privkey.pem
SMTP_DELIVERY_METHOD=direct
SMTP_ENABLE_WEBMAIL=true
SMTP_WEBMAIL_PORT=8443
SMTP_WEBMAIL_TLS=true
SMTP_WEBMAIL_SECURE_COOKIES=true
SMTP_PROVISIONING_PORT=8099
SMTP_PROVISIONING_DOMAIN=$mail_domain
SMTP_PROVISIONING_TOKEN=$provisioning_token
SMTP_CLAMAV_TRANSPORT=unix:/run/clamav/clamd.ctl
SMTP_CLAMAV_FAIL_MODE=closed
IMAP_ENABLED=true
CALDAV_ENABLED=true
CALDAV_DB_PATH=/var/lib/mail/caldav.db
DISCORD_WEBHOOK_URL=$discord_webhook
ENV
unset provisioning_token discord_webhook
if ! grep -Fxq "127.0.0.1 $hostname" /etc/hosts; then
  printf '127.0.0.1 %s\n' "$hostname" >> /etc/hosts
fi

cat > /etc/systemd/system/mail.service <<'UNIT'
[Unit]
Description=Mail staging server
After=network-online.target clamav-daemon.service
Wants=network-online.target clamav-daemon.service

[Service]
User=mail-server
Group=mail-server
SupplementaryGroups=clamav
WorkingDirectory=/var/lib/mail
EnvironmentFile=/etc/mail/mail.env
ExecStart=/opt/mail/mail-server serve
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/mail

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now mail.service certbot.timer
for attempt in $(seq 1 30); do
  missing_port=''
  for port in 25 143 443 465 587 993 8099 8443; do
    if [ -z "$(ss -H -ltn "sport = :$port")" ]; then
      missing_port=$port
      break
    fi
  done
  [ -n "$missing_port" ] || break
  if [ "$attempt" -eq 30 ]; then
    echo "Mail listener on port $missing_port did not start" >&2
    exit 1
  fi
  sleep 1
done
sh "$workdir/setup-mail-health.sh" "$workdir/mail-health.py"
/usr/local/sbin/mail-protocol-health-check --deploy-gate
