#!/usr/bin/env bash
set -euo pipefail

RELEASE_TYPE="${1:-patch}"
case "$RELEASE_TYPE" in
  patch|minor|major) ;;
  *)
    echo "usage: $0 [patch|minor|major]" >&2
    exit 2
    ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZIG="${ZIG:-$REPO_ROOT/pantry/ziglang.org/v0/bin/zig}"
BUMP_ROOT="$REPO_ROOT/pantry/zig-bump"
BUMP="$BUMP_ROOT/zig-out/bin/bump"

if [[ ! -x "$ZIG" ]]; then
  if command -v zig >/dev/null 2>&1; then
    ZIG="$(command -v zig)"
  else
    echo "missing Zig compiler: $ZIG" >&2
    exit 1
  fi
fi

if [[ ! -x "$BUMP" ]]; then
  (
    cd "$BUMP_ROOT"
    "$ZIG" build -Doptimize=ReleaseSafe
  )
fi

cd "$REPO_ROOT/packages/zig"
exec "$BUMP" "$RELEASE_TYPE" --all
