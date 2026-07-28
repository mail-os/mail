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
ZIG="$REPO_ROOT/pantry/ziglang.org/v0.16.0/bin/zig"
BUMP_ROOT="$REPO_ROOT/pantry/zig-bump"
BUMP="$BUMP_ROOT/zig-out/bin/bump"

if [[ ! -x "$ZIG" ]]; then
  echo "missing pinned Zig compiler: $ZIG" >&2
  exit 1
fi

if [[ ! -x "$BUMP" ]]; then
  (
    cd "$BUMP_ROOT"
    "$ZIG" build -Doptimize=ReleaseSafe
  )
fi

cd "$REPO_ROOT/packages/zig"
exec "$BUMP" "$RELEASE_TYPE" --all
