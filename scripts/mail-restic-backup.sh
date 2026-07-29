#!/usr/bin/env bash
set -euo pipefail

# Create a transactionally consistent local archive, then copy it into an
# authenticated, client-side encrypted Restic repository. S3's SSE-KMS remains
# enabled as a second encryption layer; Restic encryption happens first.

MAIL_ROOT="${MAIL_ROOT:-/opt/mail}"
RESTIC_CONFIG_DIR="${MAIL_RESTIC_CONFIG_DIR:-/var/lib/mail-storage/data/restic}"
RESTIC_ENV="${MAIL_RESTIC_ENV:-${RESTIC_CONFIG_DIR}/restic.env}"
BACKUP_SCRIPT="${MAIL_BACKUP_SCRIPT:-${MAIL_ROOT}/backup.sh}"
STATUS_FILE="${MAIL_RESTIC_STATUS_FILE:-${RESTIC_CONFIG_DIR}/last-success}"
CHECK_SUBSET="${MAIL_RESTIC_CHECK_SUBSET:-5%}"

die() {
  echo "mail-restic-backup: $*" >&2
  exit 1
}

[[ "${EUID}" -eq 0 ]] || die "must run as root"
mountpoint -q /var/lib/mail-storage || die "encrypted mail storage is not mounted"
[[ -x "${BACKUP_SCRIPT}" ]] || die "${BACKUP_SCRIPT} is not executable"
[[ -r "${RESTIC_ENV}" ]] || die "${RESTIC_ENV} is unavailable"
command -v restic >/dev/null 2>&1 || die "restic is not installed"

set -a
# shellcheck disable=SC1090
source "${RESTIC_ENV}"
set +a

: "${RESTIC_REPOSITORY:?RESTIC_REPOSITORY is required}"
: "${RESTIC_PASSWORD_FILE:?RESTIC_PASSWORD_FILE is required}"
: "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID is required}"
: "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY is required}"

umask 077
"${BACKUP_SCRIPT}"

latest="$(find -L "${MAIL_ROOT}/backups" -maxdepth 1 -type f -name 'mail-backup-*.tgz' \
  -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)"
[[ -n "${latest}" && -f "${latest}" ]] || die "no local backup archive was produced"
tar -tzf "${latest}" >/dev/null

declare -a inputs=("${latest}")
env_archive="${latest%.tgz}.env.tar"
[[ -f "${env_archive}" ]] && inputs+=("${env_archive}")

restic backup \
  --host "$(hostname -f 2>/dev/null || hostname)" \
  --tag mail \
  --tag production \
  "${inputs[@]}"

restic forget \
  --tag mail \
  --keep-daily 7 \
  --keep-weekly 5 \
  --keep-monthly 12 \
  --prune

restic check --read-data-subset="${CHECK_SUBSET}"

install -d -m 0700 "$(dirname "${STATUS_FILE}")"
status_tmp="${STATUS_FILE}.tmp"
{
  echo "timestamp=$(date -u +%s)"
  echo "archive=$(basename "${latest}")"
  echo "repository=${RESTIC_REPOSITORY}"
} > "${status_tmp}"
chmod 0600 "${status_tmp}"
mv "${status_tmp}" "${STATUS_FILE}"

echo "mail-restic-backup: uploaded and verified $(basename "${latest}")"
