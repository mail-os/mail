#!/usr/bin/env bash
# Provision and renew the mail UI's public certificate through the gateway webroot.
set -euo pipefail
CERTS=/etc/rpx/certs
HOST=mail.stacksjs.com
WEBROOT=/var/www/acme-challenge
TLSX=/opt/rpx-gateway/node_modules/@stacksjs/tlsx/dist/bin/cli.js
test -f "$TLSX"
mkdir -p "$WEBROOT"
before=$(sha256sum "$CERTS/$HOST.crt" 2>/dev/null || true)
if [ ! -s "$CERTS/$HOST.crt" ]; then
  bun "$TLSX" acme:issue -d "$HOST" --method http-01 --webroot "$WEBROOT" --dir "$CERTS" --prod --email chris@stacksjs.com
else
  bun "$TLSX" acme:renew --domains "$HOST" --method http-01 --webroot "$WEBROOT" --dir "$CERTS" --days 30 --prod --email chris@stacksjs.com
fi
test -s "$CERTS/$HOST.crt"
after=$(sha256sum "$CERTS/$HOST.crt")
if [ "$before" != "$after" ]; then systemctl restart rpx-gateway.service; fi
