#!/usr/bin/env bash
set -euo pipefail

# Restore the newest Restic snapshot into a disposable directory on the
# encrypted filesystem and validate the archive, databases, messages, and
# forwarding configuration without touching live data.

RESTIC_CONFIG_DIR="${MAIL_RESTIC_CONFIG_DIR:-/var/lib/mail-storage/data/restic}"
RESTIC_ENV="${MAIL_RESTIC_ENV:-${RESTIC_CONFIG_DIR}/restic.env}"
RESTORE_PARENT="${MAIL_RESTORE_CHECK_PARENT:-/var/lib/mail-storage}"

die() {
  echo "mail-restic-restore-check: $*" >&2
  exit 1
}

[[ "${EUID}" -eq 0 ]] || die "must run as root"
mountpoint -q /var/lib/mail-storage || die "encrypted mail storage is not mounted"
[[ -r "${RESTIC_ENV}" ]] || die "${RESTIC_ENV} is unavailable"
command -v restic >/dev/null 2>&1 || die "restic is not installed"

set -a
# shellcheck disable=SC1090
source "${RESTIC_ENV}"
set +a

: "${RESTIC_REPOSITORY:?RESTIC_REPOSITORY is required}"
: "${RESTIC_PASSWORD_FILE:?RESTIC_PASSWORD_FILE is required}"

restore_dir="$(mktemp -d "${RESTORE_PARENT}/restic-restore-check.XXXXXX")"
archive_dir="${restore_dir}/archive"
unpack_dir="${restore_dir}/unpacked"
cleanup() {
  find "${restore_dir}" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT

install -d -m 0700 "${archive_dir}" "${unpack_dir}"
restic restore latest --tag mail --target "${archive_dir}"

archive="$(find "${archive_dir}" -type f -name 'mail-backup-*.tgz' \
  -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)"
[[ -n "${archive}" && -f "${archive}" ]] || die "restored snapshot has no mail archive"
tar -tzf "${archive}" >/dev/null
tar -xzf "${archive}" -C "${unpack_dir}"

for database in smtp.db caldav.db; do
  if [[ -f "${unpack_dir}/${database}" ]]; then
    sqlite3 -readonly "${unpack_dir}/${database}" 'PRAGMA quick_check;' | grep -qx ok \
      || die "${database} failed quick_check"
  fi
done

message_count="$(find "${unpack_dir}/mail" -type f 2>/dev/null | wc -l)"
[[ "${message_count}" -gt 0 ]] || die "restored archive contains no messages"
[[ -f "${unpack_dir}/forwards.json" ]] || die "restored archive lacks forwarding rules"

echo "mail-restic-restore-check: ok (${message_count} messages)"
