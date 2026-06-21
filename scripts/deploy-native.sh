#!/usr/bin/env bash
# Build the mail server natively on a Linux host and hot-swap it in place.
#
# Why native (not cross-compile from macOS): cross-compiling the linux target
# from a Mac links host (Darwin) libc symbols into the binary. Building ON the
# linux box avoids that entirely. The `-Dtarget=x86_64-linux-gnu` flag is still
# passed so the build uses the *vendored* sqlite3.c (no system libsqlite3-dev
# needed) — on a linux host that's a same-OS "cross" and links cleanly.
#
# Usage:  scripts/deploy-native.sh root@HOST
# Safe:   backs up the current binary and auto-rolls-back if the service fails.
set -euo pipefail

TARGET="${1:?usage: deploy-native.sh root@HOST}"
ZIG_VER="${ZIG_VERSION:-0.16.0}"
REMOTE_DIR=/root/mailbuild

echo "==> shipping source to $TARGET:$REMOTE_DIR"
ssh "$TARGET" "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR"
tar czf - --exclude='.zig-cache' --exclude='zig-out' --exclude='*.log' \
  packages/zig pantry.jsonc pantry.lock | ssh "$TARGET" "tar xzf - -C $REMOTE_DIR"

echo "==> building on host (zig $ZIG_VER, native linux)"
ssh "$TARGET" "bash -s" <<REMOTE
set -euo pipefail
cd $REMOTE_DIR
if [ ! -x zigdist/zig ]; then
  curl -fsSL "https://ziglang.org/download/${ZIG_VER}/zig-x86_64-linux-${ZIG_VER}.tar.xz" -o zig.tar.xz
  rm -rf zigdist && mkdir zigdist && tar xJf zig.tar.xz -C zigdist --strip-components=1
fi
cd packages/zig
../../zigdist/zig build -Dtarget=x86_64-linux-gnu -Doptimize=ReleaseSafe
test -x zig-out/bin/mail
REMOTE

echo "==> hot-swapping /opt/mail/mail-server (with backup + auto-rollback)"
ssh "$TARGET" "bash -s" <<REMOTE
set -euo pipefail
BK=/opt/mail/mail-server.bak-\$(date +%s)
cp -a /opt/mail/mail-server "\$BK"
install -o mail-server -g mail-server -m 755 $REMOTE_DIR/packages/zig/zig-out/bin/mail /opt/mail/mail-server
systemctl restart mail.service
sleep 5
if [ "\$(systemctl is-active mail.service)" != "active" ]; then
  echo "service failed — rolling back"; cp -a "\$BK" /opt/mail/mail-server
  systemctl restart mail.service; exit 1
fi
echo "deployed; service active; backup at \$BK"
REMOTE
echo "==> done"
