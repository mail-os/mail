#!/usr/bin/env bash
set -euo pipefail

MAIL_DIR="${MAIL_DIR:-/opt/mail}"
BACKUP_DIR="${BACKUP_DIR:-${MAIL_DIR}/backups}"
RETAIN_DAYS="${RETAIN_DAYS:-7}"

[[ "${MAIL_DIR}" == /* && "${MAIL_DIR}" != "/" ]] || {
  echo "mail-backup: MAIL_DIR must be an absolute non-root path" >&2
  exit 1
}
[[ "${BACKUP_DIR}" == /* && "${BACKUP_DIR}" != "/" ]] || {
  echo "mail-backup: BACKUP_DIR must be an absolute non-root path" >&2
  exit 1
}

install -d -m 0700 -o root -g root "${BACKUP_DIR}"

timestamp="$(date -u +%Y%m%d-%H%M%S)"
output="${BACKUP_DIR}/mail-backup-${timestamp}.tgz"
partial="${output}.partial"
work_dir="$(mktemp -d "${BACKUP_DIR}/.mail-backup-${timestamp}.XXXXXX")"

cleanup() {
  rm -f "${partial}"
  find "${work_dir}" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT

declare -a snapshots=()
for database in smtp.db caldav.db; do
  if [[ -f "${MAIL_DIR}/${database}" ]]; then
    sqlite3 "${MAIL_DIR}/${database}" ".backup '${work_dir}/${database}'"
    sqlite3 -readonly "${work_dir}/${database}" "PRAGMA quick_check;" \
      | grep -qx ok
    snapshots+=("${database}")
  fi
done

declare -a persistent=()
for path in mail dkim forwards.json forwards.sieve cert-backups; do
  [[ -e "${MAIL_DIR}/${path}" ]] && persistent+=("${path}")
done

tar --dereference --exclude='mail/*/.*' -czf "${partial}" \
  -C "${MAIL_DIR}" "${persistent[@]}" \
  -C "${work_dir}" "${snapshots[@]}"
tar tzf "${partial}" >/dev/null
chmod 0600 "${partial}"
mv "${partial}" "${output}"

if [[ -f /etc/mail/mail.env ]]; then
  env_output="${output%.tgz}.env.tar"
  tar cf "${env_output}.partial" -C /etc/mail mail.env
  tar tf "${env_output}.partial" >/dev/null
  chmod 0600 "${env_output}.partial"
  mv "${env_output}.partial" "${env_output}"
fi

find "${BACKUP_DIR}" -maxdepth 1 -type f \
  \( -name 'mail-backup-*.tgz' -o -name 'mail-backup-*.env.tar' \) \
  -mtime "+${RETAIN_DAYS}" -delete

echo "backup written: ${output} ($(du -h "${output}" | cut -f1))"
