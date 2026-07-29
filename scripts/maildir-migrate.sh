#!/usr/bin/env bash
set -euo pipefail

# Convert the server's historical layout into Maildir++ without changing the
# paths used by existing server code. A folder is stored canonically at
# `.Folder/{tmp,new,cur}` and the historical `Folder` path is a relative
# symlink to `.Folder/cur`.

COMMAND="${1:-status}"
MAIL_ROOT="${MAIL_ROOT:-/opt/mail/mail}"

die() {
  echo "maildir-migrate: $*" >&2
  exit 1
}

[[ "${EUID}" -eq 0 ]] || die "must run as root"
[[ "${MAIL_ROOT}" == /* && "${MAIL_ROOT}" != "/" ]] || die "MAIL_ROOT must be an absolute non-root path"
[[ -d "${MAIL_ROOT}" ]] || die "${MAIL_ROOT} does not exist"

mail_was_active=false
if [[ "${COMMAND}" == "migrate" ]] && systemctl is-active --quiet mail.service; then
  mail_was_active=true
  systemctl stop mail.service
fi

cleanup() {
  if [[ "${mail_was_active}" == "true" ]]; then
    systemctl start mail.service
  fi
}
trap cleanup EXIT

folder_count=0
mailbox_count=0

inspect_mailbox() {
  local mailbox="$1"
  local entry name canonical target

  for required in tmp new cur; do
    [[ -d "${mailbox}/${required}" ]] || {
      [[ "${COMMAND}" == "migrate" ]] && install -d -m 0700 "${mailbox}/${required}"
    }
  done

  while IFS= read -r -d '' entry; do
    name="${entry##*/}"
    [[ "${name}" != "tmp" && "${name}" != "new" && "${name}" != "cur" ]] || continue
    [[ "${name}" != .* ]] || continue

    canonical="${mailbox}/.${name}"
    if [[ -L "${entry}" ]]; then
      target="$(readlink "${entry}")"
      [[ "${target}" == ".${name}/cur" ]] \
        || die "${entry} points to unexpected target ${target}"
      [[ -d "${canonical}/tmp" && -d "${canonical}/new" && -d "${canonical}/cur" ]] \
        || die "${canonical} is incomplete"
      if [[ "${COMMAND}" == "migrate" ]]; then
        chown -R --reference="${mailbox}" "${canonical}"
        chmod 0700 "${canonical}" "${canonical}/tmp" "${canonical}/new" "${canonical}/cur"
        chown -h --reference="${mailbox}" "${entry}"
      fi
      folder_count=$((folder_count + 1))
      continue
    fi
    [[ -d "${entry}" ]] || continue

    if [[ "${COMMAND}" == "migrate" ]]; then
      install -d -m 0700 "${canonical}/tmp" "${canonical}/new" "${canonical}/cur"
      while IFS= read -r -d '' message; do
        base="${message##*/}"
        [[ ! -e "${canonical}/cur/${base}" ]] \
          || die "collision while moving ${message}"
        mv "${message}" "${canonical}/cur/${base}"
      done < <(find "${entry}" -mindepth 1 -maxdepth 1 -type f -print0)

      # Some historical folders already used Folder/{tmp,new,cur}. Preserve
      # the delivery state of every message while moving those three standard
      # components below the Maildir++ dot-folder.
      for component in tmp new cur; do
        [[ -d "${entry}/${component}" ]] || continue
        while IFS= read -r -d '' message; do
          base="${message##*/}"
          [[ ! -e "${canonical}/${component}/${base}" ]] \
            || die "collision while moving ${message}"
          mv "${message}" "${canonical}/${component}/${base}"
        done < <(find "${entry}/${component}" -mindepth 1 -maxdepth 1 -type f -print0)
        rmdir "${entry}/${component}" \
          || die "${entry}/${component} contains unsupported nested entries"
      done
      rmdir "${entry}" || die "${entry} contains unsupported nested entries"
      ln -s ".${name}/cur" "${entry}"
      chown -R --reference="${mailbox}" "${canonical}"
      chmod 0700 "${canonical}" "${canonical}/tmp" "${canonical}/new" "${canonical}/cur"
      chown -h --reference="${mailbox}" "${entry}"
    fi
    folder_count=$((folder_count + 1))
  done < <(find "${mailbox}" -mindepth 1 -maxdepth 1 \( -type d -o -type l \) -print0)
}

while IFS= read -r -d '' mailbox; do
  inspect_mailbox "${mailbox}"
  mailbox_count=$((mailbox_count + 1))
done < <(find -L "${MAIL_ROOT}" -mindepth 1 -maxdepth 1 -type d -print0)

if [[ "${COMMAND}" == "migrate" ]]; then
  echo "maildir-migrate: migrated ${mailbox_count} mailboxes and ${folder_count} folders"
elif [[ "${COMMAND}" == "status" ]]; then
  echo "maildir-migrate: ${mailbox_count} mailboxes, ${folder_count} compatible folders"
else
  die "usage: $0 {status|migrate}"
fi
