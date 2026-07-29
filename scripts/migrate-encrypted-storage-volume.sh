#!/usr/bin/env bash
set -euo pipefail

# Move the existing LUKS image onto a dedicated block volume without changing
# its UUID, keyslots, or public path. `prepare` intentionally leaves mail
# locked; the external-key controller must unlock and validate before
# `finalize` removes the root-disk rollback image.

COMMAND="${1:-status}"
DEVICE="${MAIL_VOLUME_DEVICE:-${2:-}}"
VOLUME_MOUNT="${MAIL_VOLUME_MOUNT:-/var/lib/mail-volume}"
IMAGE_PATH="${MAIL_ENCRYPTED_IMAGE:-/var/lib/mail-storage.luks}"
TARGET_SIZE="${MAIL_ENCRYPTED_IMAGE_SIZE:-16G}"
VOLUME_IMAGE="${VOLUME_MOUNT}/mail-storage.luks"
ROOT_BACKUP="${IMAGE_PATH}.root-backup"

die() {
  echo "mail-volume-migrate: $*" >&2
  exit 1
}

[[ "${EUID}" -eq 0 ]] || die "must run as root"
[[ "${VOLUME_MOUNT}" == /* && "${VOLUME_MOUNT}" != "/" ]] || die "invalid mount path"
[[ "${IMAGE_PATH}" == /* && "${IMAGE_PATH}" != "/" ]] || die "invalid image path"

ensure_volume_mount() {
  [[ -n "${DEVICE}" ]] || die "MAIL_VOLUME_DEVICE or device argument is required"
  [[ -b "${DEVICE}" ]] || die "${DEVICE} is not a block device"
  install -d -m 0700 "${VOLUME_MOUNT}"

  if ! blkid "${DEVICE}" >/dev/null 2>&1; then
    mkfs.ext4 -q -L mail-volume "${DEVICE}"
  fi
  uuid="$(blkid -s UUID -o value "${DEVICE}")"
  [[ -n "${uuid}" ]] || die "could not resolve volume UUID"

  if ! grep -qE "^[^#]+[[:space:]]+${VOLUME_MOUNT//\//\\/}[[:space:]]" /etc/fstab; then
    echo "UUID=${uuid} ${VOLUME_MOUNT} ext4 defaults,noatime,nodev,nosuid 0 2" >> /etc/fstab
  fi
  mountpoint -q "${VOLUME_MOUNT}" || mount "${VOLUME_MOUNT}"
  chmod 0700 "${VOLUME_MOUNT}"
}

prepare() {
  [[ -f "${IMAGE_PATH}" && ! -L "${IMAGE_PATH}" ]] \
    || die "${IMAGE_PATH} must be the current root-disk image"
  [[ ! -e "${ROOT_BACKUP}" ]] || die "${ROOT_BACKUP} already exists"
  ensure_volume_mount

  /usr/local/sbin/mail-storage-external lock
  if [[ -e "${VOLUME_IMAGE}" ]]; then
    root_size="$(stat -c %s "${IMAGE_PATH}")"
    if ! cmp -n "${root_size}" "${IMAGE_PATH}" "${VOLUME_IMAGE}"; then
      cp --sparse=always --reflink=auto "${IMAGE_PATH}" "${VOLUME_IMAGE}.new"
      chmod 0600 "${VOLUME_IMAGE}.new"
      cmp -s "${IMAGE_PATH}" "${VOLUME_IMAGE}.new" || die "refreshed image failed byte comparison"
      sync "${VOLUME_IMAGE}.new"
      mv "${VOLUME_IMAGE}.new" "${VOLUME_IMAGE}"
    fi
  else
    cp --sparse=always --reflink=auto "${IMAGE_PATH}" "${VOLUME_IMAGE}.new"
    chmod 0600 "${VOLUME_IMAGE}.new"
    cmp -s "${IMAGE_PATH}" "${VOLUME_IMAGE}.new" || die "copied image failed byte comparison"
    sync "${VOLUME_IMAGE}.new"
    mv "${VOLUME_IMAGE}.new" "${VOLUME_IMAGE}"
  fi
  mv "${IMAGE_PATH}" "${ROOT_BACKUP}"
  ln -s "${VOLUME_IMAGE}" "${IMAGE_PATH}"
  truncate -s "${TARGET_SIZE}" "${VOLUME_IMAGE}"
  sync "${VOLUME_IMAGE}"
  echo "mail-volume-migrate: prepared; external unlock is required"
}

finalize() {
  mountpoint -q /var/lib/mail-storage || die "encrypted mail storage is not mounted"
  systemctl is-active --quiet mail.service || die "mail is not active"
  [[ -L "${IMAGE_PATH}" && "$(readlink "${IMAGE_PATH}")" == "${VOLUME_IMAGE}" ]] \
    || die "mail image does not point to dedicated volume"

  loop_device="$(cryptsetup status mail-storage | awk '/device:/ { print $2; exit }')"
  [[ -n "${loop_device}" ]] || die "could not identify loop device"
  losetup -c "${loop_device}"
  resize2fs /dev/mapper/mail-storage
  rm -f "${ROOT_BACKUP}"
  echo "mail-volume-migrate: finalized"
}

rollback() {
  /usr/local/sbin/mail-storage-external lock
  [[ -f "${ROOT_BACKUP}" ]] || die "root rollback image is unavailable"
  [[ -L "${IMAGE_PATH}" ]] || die "${IMAGE_PATH} is not a symlink"
  unlink "${IMAGE_PATH}"
  mv "${ROOT_BACKUP}" "${IMAGE_PATH}"
  echo "mail-volume-migrate: rolled back; external unlock is required"
}

status() {
  findmnt "${VOLUME_MOUNT}" || true
  ls -l "${IMAGE_PATH}" "${VOLUME_IMAGE}" "${ROOT_BACKUP}" 2>/dev/null || true
  df -h "${VOLUME_MOUNT}" 2>/dev/null || true
}

case "${COMMAND}" in
  prepare) prepare ;;
  finalize) finalize ;;
  rollback) rollback ;;
  status) status ;;
  *) die "usage: $0 {prepare|finalize|rollback|status} [device]" ;;
esac
