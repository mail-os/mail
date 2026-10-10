#!/usr/bin/env bash
# Provision and renew the mail UI's public certificate through the gateway webroot.
set -euo pipefail
CERTS=/etc/rpx/certs
CONFIG=/etc/rpx/sites.d/mail.json
WEBROOT=/var/www/acme-challenge
TLSX=/opt/rpx-gateway/node_modules/@stacksjs/tlsx/dist/bin/cli.js
test -f "$TLSX"
mkdir -p "$WEBROOT"
hosts=$(python3 -c 'import json, sys; print("\n".join(json.load(open(sys.argv[1]))["productionCerts"]["certsDirServerNames"]))' "$CONFIG")
test -n "$hosts"
changed=false
while IFS= read -r host; do
  before=$(sha256sum "$CERTS/$host.crt" 2>/dev/null || true)
  if [ ! -s "$CERTS/$host.crt" ]; then
    bun "$TLSX" acme:issue -d "$host" --method http-01 --webroot "$WEBROOT" --dir "$CERTS" --prod --email chris@stacksjs.com
  else
    bun "$TLSX" acme:renew --domains "$host" --method http-01 --webroot "$WEBROOT" --dir "$CERTS" --days 30 --prod --email chris@stacksjs.com
  fi
  test -s "$CERTS/$host.crt"
  after=$(sha256sum "$CERTS/$host.crt")
  if [ "$before" != "$after" ]; then changed=true; fi
done <<< "$hosts"
if [ "$changed" = true ]; then systemctl restart rpx-gateway.service; fi
