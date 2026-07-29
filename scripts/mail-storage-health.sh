#!/usr/bin/env bash
set -euo pipefail

MOUNT_PATH="${MAIL_ENCRYPTED_MOUNT:-/var/lib/mail-storage}"
STATUS_FILE="${MAIL_RESTIC_STATUS_FILE:-${MOUNT_PATH}/data/restic/last-success}"
WARN_PERCENT="${MAIL_STORAGE_WARN_PERCENT:-70}"
CRITICAL_PERCENT="${MAIL_STORAGE_CRITICAL_PERCENT:-85}"
MAX_BACKUP_AGE="${MAIL_BACKUP_MAX_AGE_SECONDS:-90000}"

die() {
  echo "mail-storage-health: $*" >&2
  exit 1
}

mountpoint -q "${MOUNT_PATH}" || die "${MOUNT_PATH} is not mounted"
usage="$(df -P "${MOUNT_PATH}" | awk 'NR == 2 { gsub(/%/, "", $5); print $5 }')"
[[ "${usage}" =~ ^[0-9]+$ ]] || die "could not read filesystem usage"

if (( usage >= CRITICAL_PERCENT )); then
  die "encrypted storage is ${usage}% full (critical threshold ${CRITICAL_PERCENT}%)"
elif (( usage >= WARN_PERCENT )); then
  echo "mail-storage-health: warning: encrypted storage is ${usage}% full" >&2
fi

[[ -r "${STATUS_FILE}" ]] || die "no successful off-host backup status exists"
timestamp="$(awk -F= '$1 == "timestamp" { print $2; exit }' "${STATUS_FILE}")"
[[ "${timestamp}" =~ ^[0-9]+$ ]] || die "backup status timestamp is invalid"
age="$(( $(date -u +%s) - timestamp ))"
(( age <= MAX_BACKUP_AGE )) || die "latest verified off-host backup is ${age}s old"

echo "mail-storage-health: ok (usage=${usage}%, backup_age=${age}s)"
