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
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The toolchain is pinned in pantry.jsonc; pantry spells the build metadata
# separator as `_`, ziglang.org as `+`. Read the pin rather than hardcoding it
# so the host never builds with a toolchain the repo has moved off.
ZIG_VER="${ZIG_VERSION:-$(sed -n 's/.*"ziglang.org"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$REPO_ROOT/pantry.jsonc" | head -1 | tr '_' '+')}"
: "${ZIG_VER:?could not read the ziglang.org pin from pantry.jsonc}"
# Tagged releases live under /download/<ver>/, nightlies under /builds/.
case "$ZIG_VER" in
  *-dev*) ZIG_URL="https://ziglang.org/builds/zig-x86_64-linux-${ZIG_VER}.tar.xz" ;;
  *)      ZIG_URL="https://ziglang.org/download/${ZIG_VER}/zig-x86_64-linux-${ZIG_VER}.tar.xz" ;;
esac
REMOTE_DIR=/root/mailbuild

echo "==> shipping source to $TARGET:$REMOTE_DIR"
ssh "$TARGET" "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR"
tar czf - --exclude='.zig-cache' --exclude='zig-out' --exclude='*.log' \
  packages/zig pantry.jsonc pantry.lock | ssh "$TARGET" "tar xzf - -C $REMOTE_DIR"

echo "==> building on host (zig $ZIG_VER, native linux)"
ssh "$TARGET" "bash -s" <<REMOTE
set -euo pipefail
# Keyed by version and kept OUTSIDE \$REMOTE_DIR (which is wiped every deploy),
# so the toolchain survives across deploys but a pin bump still refetches.
ZIGDIST=/root/zigdist-${ZIG_VER}
if [ ! -x "\$ZIGDIST/zig" ]; then
  curl -fsSL "${ZIG_URL}" -o /root/zig.tar.xz
  rm -rf "\$ZIGDIST" && mkdir -p "\$ZIGDIST"
  tar xJf /root/zig.tar.xz -C "\$ZIGDIST" --strip-components=1
  rm -f /root/zig.tar.xz
fi
cd $REMOTE_DIR/packages/zig
"\$ZIGDIST/zig" build -Dtarget=x86_64-linux-gnu -Doptimize=ReleaseSafe
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
