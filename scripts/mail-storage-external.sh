#!/usr/bin/env bash
set -euo pipefail

# Manage an externally escrowed LUKS2 mail volume. In external mode no volume
# key or cloud credential is stored on the mail host. `unlock` accepts the raw
# key on stdin, passes it directly to cryptsetup, and never writes it to disk.

COMMAND="${1:-status}"
MAIL_SERVICE="${MAIL_SERVICE:-mail}"
IMAGE_PATH="${MAIL_ENCRYPTED_IMAGE:-/var/lib/mail-storage.luks}"
MOUNT_PATH="${MAIL_ENCRYPTED_MOUNT:-/var/lib/mail-storage}"
MAPPER_NAME="${MAIL_ENCRYPTED_MAPPER:-mail-storage}"
CREDENTIAL_PATH="${MAIL_ENCRYPTED_CREDENTIAL:-/etc/credstore.encrypted/mail-storage-key.cred}"
UNIT_PATH="/etc/systemd/system/mail-storage.service"
UNIT_BACKUP="/etc/systemd/system/mail-storage.service.machine-bound-backup"
MAIL_DROPIN="/etc/systemd/system/${MAIL_SERVICE}.service.d/encrypted-storage.conf"
BACKUP_DROPIN="/etc/systemd/system/mail-backup.service.d/encrypted-storage.conf"

die() {
  echo "mail-storage: $*" >&2
  return 1
}

[[ "${EUID}" -eq 0 ]] || die "must run as root"
[[ "${IMAGE_PATH}" == /* && "${IMAGE_PATH}" != "/" ]] || die "invalid image path"
[[ "${MOUNT_PATH}" == /* && "${MOUNT_PATH}" != "/" ]] || die "invalid mount path"
[[ "${MAPPER_NAME}" =~ ^[A-Za-z0-9_.+-]+$ ]] || die "invalid mapper name"

CRYPTSETUP="$(command -v cryptsetup || true)"
MOUNT_BIN="$(command -v mount || true)"
UMOUNT_BIN="$(command -v umount || true)"
MOUNTPOINT_BIN="$(command -v mountpoint || true)"
LOSETUP_BIN="$(command -v losetup || true)"
[[ -n "${CRYPTSETUP}" && -n "${MOUNT_BIN}" && -n "${UMOUNT_BIN}" && -n "${MOUNTPOINT_BIN}" && -n "${LOSETUP_BIN}" ]] \
  || die "cryptsetup and mount utilities are required"

configure_external() {
  [[ -f "${IMAGE_PATH}" ]] || die "${IMAGE_PATH} does not exist"
  [[ -f "${CREDENTIAL_PATH}" ]] || die "machine-bound credential is unavailable for rollback"

  systemctl stop "${MAIL_SERVICE}.service" 2>/dev/null || true
  systemctl stop mail-backup.service 2>/dev/null || true
  systemctl stop mail-storage.service 2>/dev/null || true

  if [[ -f "${UNIT_PATH}" && ! -f "${UNIT_BACKUP}" ]]; then
    cp -p "${UNIT_PATH}" "${UNIT_BACKUP}"
  fi

  cat > "${UNIT_PATH}" <<EOF
[Unit]
Description=Externally unlocked encrypted mail data filesystem
Before=${MAIL_SERVICE}.service mail-backup.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${MOUNTPOINT_BIN} -q ${MOUNT_PATH}
ExecStop=-${UMOUNT_BIN} ${MOUNT_PATH}
ExecStop=-${CRYPTSETUP} close ${MAPPER_NAME}
TimeoutStopSec=120
EOF

  install -d -m 0755 "$(dirname "${MAIL_DROPIN}")" "$(dirname "${BACKUP_DROPIN}")"
  cat > "${MAIL_DROPIN}" <<EOF
[Unit]
After=mail-storage.service

[Service]
ExecCondition=${MOUNTPOINT_BIN} -q ${MOUNT_PATH}
EOF
  cp "${MAIL_DROPIN}" "${BACKUP_DROPIN}"

  systemctl disable mail-storage.service >/dev/null 2>&1 || true
  systemctl daemon-reload
  echo "mail-storage: external mode configured; volume is locked"
}

unlock_external() {
  [[ -f "${IMAGE_PATH}" ]] || die "${IMAGE_PATH} does not exist"

  if ! "${CRYPTSETUP}" status "${MAPPER_NAME}" >/dev/null 2>&1; then
    backing_file="$(readlink -f "${IMAGE_PATH}")"
    loop_device="$("${LOSETUP_BIN}" -j "${backing_file}" | awk -F: 'NR == 1 { print $1 }')"
    created_loop=false
    if [[ -z "${loop_device}" ]]; then
      loop_device="$("${LOSETUP_BIN}" --find --show "${backing_file}")"
      created_loop=true
    fi
    # cryptsetup consumes the raw key from this process's stdin. No shell
    # variable, argument, environment entry, or persistent file holds it.
    if ! "${CRYPTSETUP}" open --type luks2 --key-file - "${loop_device}" "${MAPPER_NAME}"; then
      [[ "${created_loop}" == "true" ]] && "${LOSETUP_BIN}" -d "${loop_device}" || true
      return 1
    fi
  else
    # Consume stdin even when already unlocked so callers never get a broken
    # pipe while streaming a secret.
    dd of=/dev/null status=none
  fi

  if ! "${MOUNTPOINT_BIN}" -q "${MOUNT_PATH}"; then
    install -d -m 0750 -o root -g mail-server "${MOUNT_PATH}"
    "${MOUNT_BIN}" -o noatime,nodev,nosuid "/dev/mapper/${MAPPER_NAME}" "${MOUNT_PATH}"
  fi

  systemctl reset-failed mail-storage.service "${MAIL_SERVICE}.service" 2>/dev/null || true
  systemctl start mail-storage.service
  systemctl start "${MAIL_SERVICE}.service"
  sleep 2
  systemctl is-active --quiet mail-storage.service || die "storage unit is not active"
  systemctl is-active --quiet "${MAIL_SERVICE}.service" || die "mail service is not active"
  echo "mail-storage: unlocked; mail is active"
}

lock_external() {
  systemctl stop mail-backup.service 2>/dev/null || true
  systemctl stop "${MAIL_SERVICE}.service" 2>/dev/null || true
  if systemctl is-active --quiet mail-storage.service; then
    systemctl stop mail-storage.service
  else
    "${MOUNTPOINT_BIN}" -q "${MOUNT_PATH}" && "${UMOUNT_BIN}" "${MOUNT_PATH}" || true
    "${CRYPTSETUP}" status "${MAPPER_NAME}" >/dev/null 2>&1 \
      && "${CRYPTSETUP}" close "${MAPPER_NAME}" || true
  fi
  backing_file="$(readlink -f "${IMAGE_PATH}")"
  while IFS=: read -r loop_device _; do
    [[ -n "${loop_device}" ]] && "${LOSETUP_BIN}" -d "${loop_device}" 2>/dev/null || true
  done < <("${LOSETUP_BIN}" -j "${backing_file}")
  echo "mail-storage: locked; mail is stopped"
}

finalize_external() {
  "${MOUNTPOINT_BIN}" -q "${MOUNT_PATH}" || die "refusing to remove local credential while storage is locked"
  systemctl is-active --quiet "${MAIL_SERVICE}.service" \
    || die "refusing to remove local credential while mail is inactive"
  [[ -f "${UNIT_BACKUP}" ]] || die "machine-bound unit backup is missing"

  shred -u "${CREDENTIAL_PATH}" 2>/dev/null || rm -f "${CREDENTIAL_PATH}"
  chmod 0600 "${UNIT_BACKUP}"
  echo "mail-storage: local volume credential removed; external mode finalized"
}

rollback_machine() {
  [[ -f "${UNIT_BACKUP}" ]] || die "machine-bound unit backup is missing"
  [[ -f "${CREDENTIAL_PATH}" ]] || die "machine-bound credential is missing"

  systemctl stop "${MAIL_SERVICE}.service" 2>/dev/null || true
  systemctl stop mail-storage.service 2>/dev/null || true
  cp -p "${UNIT_BACKUP}" "${UNIT_PATH}"
  cat > "${MAIL_DROPIN}" <<EOF
[Unit]
Requires=mail-storage.service
After=mail-storage.service
EOF
  cp "${MAIL_DROPIN}" "${BACKUP_DROPIN}"
  systemctl daemon-reload
  systemctl enable --now mail-storage.service
  systemctl reset-failed "${MAIL_SERVICE}.service" 2>/dev/null || true
  systemctl start "${MAIL_SERVICE}.service"
  echo "mail-storage: restored machine-bound unlock mode"
}

status_external() {
  local mode="machine-bound"
  if [[ ! -f "${CREDENTIAL_PATH}" ]]; then
    mode="external"
  elif ! grep -q '^LoadCredentialEncrypted=' "${UNIT_PATH}" 2>/dev/null; then
    mode="external-pending-finalization"
  fi
  echo "mode=${mode}"
  if [[ -f "${CREDENTIAL_PATH}" ]]; then
    echo "local_credential=present"
  else
    echo "local_credential=absent"
  fi
  if "${CRYPTSETUP}" status "${MAPPER_NAME}" >/dev/null 2>&1; then
    echo "mapper=active"
  else
    echo "mapper=locked"
  fi
  if "${MOUNTPOINT_BIN}" -q "${MOUNT_PATH}"; then
    echo "mount=active"
  else
    echo "mount=inactive"
  fi
  echo "mail=$(systemctl is-active "${MAIL_SERVICE}.service" 2>/dev/null || true)"
  echo "backup_timer=$(systemctl is-active mail-backup.timer 2>/dev/null || true)"
}

add_recovery_key() {
  local key_dir current_key recovery_key
  key_dir="$(mktemp -d /run/mail-storage-recovery.XXXXXX)"
  current_key="${key_dir}/current"
  recovery_key="${key_dir}/recovery"
  cleanup_recovery_keys() {
    [[ -n "${current_key:-}" ]] && shred -u "${current_key}" 2>/dev/null || true
    [[ -n "${recovery_key:-}" ]] && shred -u "${recovery_key}" 2>/dev/null || true
    [[ -n "${current_key:-}" ]] && rm -f "${current_key}" || true
    [[ -n "${recovery_key:-}" ]] && rm -f "${recovery_key}" || true
    [[ -n "${key_dir:-}" ]] && rmdir "${key_dir}" 2>/dev/null || true
  }
  trap cleanup_recovery_keys EXIT

  dd if=/dev/stdin of="${current_key}" bs=64 count=1 iflag=fullblock status=none
  dd if=/dev/stdin of="${recovery_key}" bs=64 count=1 iflag=fullblock status=none
  [[ "$(stat -c %s "${current_key}")" -eq 64 ]] || die "invalid current key length"
  [[ "$(stat -c %s "${recovery_key}")" -eq 64 ]] || die "invalid recovery key length"
  chmod 0400 "${current_key}" "${recovery_key}"

  "${CRYPTSETUP}" luksAddKey \
    --key-file "${current_key}" \
    --new-keyfile "${recovery_key}" \
    "${IMAGE_PATH}"
  "${CRYPTSETUP}" open \
    --test-passphrase \
    --type luks2 \
    --key-file "${recovery_key}" \
    "${IMAGE_PATH}"
  echo "mail-storage: independent recovery keyslot added and verified"
}

remove_keyslot() {
  local slot="${2:-}" key_dir current_key
  [[ "${slot}" =~ ^[0-9]+$ ]] || die "a numeric LUKS keyslot is required"
  key_dir="$(mktemp -d /run/mail-storage-keyslot.XXXXXX)"
  current_key="${key_dir}/current"
  cleanup_keyslot_key() {
    [[ -n "${current_key:-}" ]] && shred -u "${current_key}" 2>/dev/null || true
    [[ -n "${current_key:-}" ]] && rm -f "${current_key}" || true
    [[ -n "${key_dir:-}" ]] && rmdir "${key_dir}" 2>/dev/null || true
  }
  trap cleanup_keyslot_key EXIT

  dd if=/dev/stdin of="${current_key}" bs=64 count=1 iflag=fullblock status=none
  [[ "$(stat -c %s "${current_key}")" -eq 64 ]] || die "invalid current key length"
  chmod 0400 "${current_key}"
  "${CRYPTSETUP}" luksKillSlot --key-file "${current_key}" "${IMAGE_PATH}" "${slot}"
  echo "mail-storage: removed keyslot ${slot}"
}

case "${COMMAND}" in
  configure-external) configure_external ;;
  unlock) unlock_external ;;
  lock) lock_external ;;
  finalize-external) finalize_external ;;
  rollback-machine) rollback_machine ;;
  add-recovery-key) add_recovery_key ;;
  remove-keyslot) remove_keyslot "$@" ;;
  status) status_external ;;
  *)
    die "usage: $0 {configure-external|unlock|lock|finalize-external|rollback-machine|add-recovery-key|remove-keyslot <slot>|status}"
    ;;
esac
