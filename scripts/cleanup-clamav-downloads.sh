#!/usr/bin/env bash
# Interrupted freshclam downloads can leave large temporary signature files.
# Keep recent downloads and the installed database intact.
set -euo pipefail

find "${CLAMAV_TMP_DIR:-/tmp}" -xdev -mindepth 1 -maxdepth 1 \
  -type f -name 'clamav-*.tmp' -mtime +2 -print -delete
