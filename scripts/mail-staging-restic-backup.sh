#!/usr/bin/env bash
set -euo pipefail
umask 077

die() {
  echo "mail-staging-restic-backup: $*" >&2
  exit 1
}

[[ $# -eq 3 ]] || die "expected the Mail data directory, environment file, and executable"
source_dir=$1
mail_env=$2
mail_binary=$3
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

grep -Fxq 'SMTP_PROFILE=staging' "$mail_env" || die "requires a staging Mail instance"
[[ -f "$source_dir/smtp.db" && -d "$source_dir/mail" ]] || die "Mail storage is unavailable"
[[ -x "$mail_binary" ]] || die "Mail executable is unavailable"
[[ "${RESTIC_REPOSITORY:-}" =~ ^s3:https://s3\.[a-z0-9-]+\.amazonaws\.com/[a-z0-9][a-z0-9.-]+/staging/backups/[a-z0-9][a-z0-9.-]*$ ]] \
  || die "requires a dedicated staging S3 repository"
[[ -d "${STATE_DIRECTORY:?the service must set STATE_DIRECTORY}" ]] || die "backup state directory is unavailable"
export RESTIC_PASSWORD_FILE="${CREDENTIALS_DIRECTORY:?the service must provide the Restic credential}/restic-password"
[[ -s "$RESTIC_PASSWORD_FILE" ]] || die "Restic credential is unavailable"

work_dir=$(mktemp -d "$STATE_DIRECTORY/backup.XXXXXXXX")
trap 'find "$work_dir" -depth -delete' EXIT
MAIL_DIR="$source_dir" BACKUP_DIR="$work_dir" MAIL_BACKUP_BIN="$mail_binary" \
  MAIL_BACKUP_ENV_FILE='' bash "$script_dir/mail-backup.sh"
archives=("$work_dir"/mail-backup-*.tgz)
[[ ${#archives[@]} -eq 1 && -f "${archives[0]}" ]] || die "expected one fresh Mail archive"

restic --no-cache backup --tag mail-staging "${archives[0]}"
# Temporary archive paths differ per run. Retention groups snapshots by host and tag.
restic --no-cache forget --tag mail-staging --group-by host,tags --keep-daily 7 --keep-weekly 5 --prune
restic --no-cache check --read-data

{
  printf 'timestamp=%s\n' "$(date -u +%s)"
  printf 'archive=%s\n' "$(basename "${archives[0]}")"
} > "$work_dir/last-success"
mv -fT "$work_dir/last-success" "$STATE_DIRECTORY/last-success"
