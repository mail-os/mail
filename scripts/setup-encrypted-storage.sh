#!/usr/bin/env bash
set -euo pipefail

# Provision a LUKS2-backed filesystem for mail data and migrate an existing
# /opt/mail installation without changing the paths used by the server.
#
# The random volume key is never left on persistent storage in plaintext.
# systemd-creds wraps it with the host credential secret and exposes it only to
# mail-storage.service through a private, read-only runtime credential.

MAIL_ROOT="${MAIL_ROOT:-/opt/mail}"
MAIL_SERVICE="${MAIL_SERVICE:-mail}"
IMAGE_PATH="${MAIL_ENCRYPTED_IMAGE:-/var/lib/mail-storage.luks}"
IMAGE_SIZE="${MAIL_ENCRYPTED_IMAGE_SIZE:-2G}"
MOUNT_PATH="${MAIL_ENCRYPTED_MOUNT:-/var/lib/mail-storage}"
MAPPER_NAME="${MAIL_ENCRYPTED_MAPPER:-mail-storage}"
CREDENTIAL_PATH="${MAIL_ENCRYPTED_CREDENTIAL:-/etc/credstore.encrypted/mail-storage-key.cred}"
UNIT_PATH="/etc/systemd/system/mail-storage.service"
DROPIN_PATH="/etc/systemd/system/${MAIL_SERVICE}.service.d/encrypted-storage.conf"

die() {
  echo "encrypted-storage: $*" >&2
  return 1
}

[[ "${EUID}" -eq 0 ]] || die "must run as root"
[[ "${MAIL_ROOT}" == /* && "${MAIL_ROOT}" != "/" ]] || die "MAIL_ROOT must be an absolute non-root path"
[[ "${IMAGE_PATH}" == /* && "${IMAGE_PATH}" != "/" ]] || die "MAIL_ENCRYPTED_IMAGE must be an absolute file path"
[[ "${MOUNT_PATH}" == /* && "${MOUNT_PATH}" != "/" ]] || die "MAIL_ENCRYPTED_MOUNT must be an absolute non-root path"
[[ "${MAPPER_NAME}" =~ ^[A-Za-z0-9_.+-]+$ ]] || die "invalid mapper name"

CRYPTSETUP="$(command -v cryptsetup || true)"
MKFS_EXT4="$(command -v mkfs.ext4 || true)"
SYSTEMD_CREDS="$(command -v systemd-creds || true)"
MOUNT_BIN="$(command -v mount || true)"
UMOUNT_BIN="$(command -v umount || true)"

[[ -n "${CRYPTSETUP}" ]] || die "cryptsetup is required"
[[ -n "${MKFS_EXT4}" ]] || die "mkfs.ext4 is required"
[[ -n "${SYSTEMD_CREDS}" ]] || die "systemd-creds is required"
[[ -n "${MOUNT_BIN}" && -n "${UMOUNT_BIN}" ]] || die "mount and umount are required"

install -d -m 0700 "$(dirname "${CREDENTIAL_PATH}")"
install -d -m 0750 -o root -g mail-server "${MOUNT_PATH}"
install -d -m 0755 "$(dirname "${IMAGE_PATH}")"

created_image=0
temporary_key=""
cleanup_key() {
  if [[ -n "${temporary_key}" && -f "${temporary_key}" ]]; then
    shred -u "${temporary_key}" 2>/dev/null || rm -f "${temporary_key}"
  fi
}
trap cleanup_key EXIT

if [[ ! -f "${IMAGE_PATH}" ]]; then
  [[ ! -e "${CREDENTIAL_PATH}" ]] || die "credential exists but encrypted image does not"

  temporary_key="$(mktemp /run/mail-storage-key.XXXXXX)"
  chmod 0400 "${temporary_key}"
  dd if=/dev/urandom of="${temporary_key}" bs=64 count=1 status=none

  echo "encrypted-storage: creating ${IMAGE_SIZE} LUKS2 image"
  fallocate -l "${IMAGE_SIZE}" "${IMAGE_PATH}"
  chmod 0600 "${IMAGE_PATH}"
  "${CRYPTSETUP}" luksFormat \
    --batch-mode \
    --type luks2 \
    --cipher aes-xts-plain64 \
    --key-size 512 \
    --hash sha512 \
    --pbkdf argon2id \
    --iter-time 5000 \
    --key-file "${temporary_key}" \
    "${IMAGE_PATH}"

  "${CRYPTSETUP}" open --type luks2 --key-file "${temporary_key}" "${IMAGE_PATH}" "${MAPPER_NAME}"
  "${MKFS_EXT4}" -q -L mail-storage "/dev/mapper/${MAPPER_NAME}"
  "${CRYPTSETUP}" close "${MAPPER_NAME}"

  "${SYSTEMD_CREDS}" encrypt \
    --name=mail-storage-key \
    "${temporary_key}" \
    "${CREDENTIAL_PATH}"
  chmod 0600 "${CREDENTIAL_PATH}"
  created_image=1
elif [[ ! -f "${CREDENTIAL_PATH}" ]]; then
  die "encrypted image exists but ${CREDENTIAL_PATH} is missing"
fi

cat > "${UNIT_PATH}" <<EOF
[Unit]
Description=Encrypted mail data filesystem
After=local-fs.target
Before=${MAIL_SERVICE}.service

[Service]
Type=oneshot
RemainAfterExit=yes
LoadCredentialEncrypted=mail-storage-key:${CREDENTIAL_PATH}
ExecStart=${CRYPTSETUP} open --type luks2 --key-file %d/mail-storage-key ${IMAGE_PATH} ${MAPPER_NAME}
ExecStart=${MOUNT_BIN} -o noatime,nodev,nosuid /dev/mapper/${MAPPER_NAME} ${MOUNT_PATH}
ExecStop=-${UMOUNT_BIN} ${MOUNT_PATH}
ExecStop=-${CRYPTSETUP} close ${MAPPER_NAME}
TimeoutStartSec=0
TimeoutStopSec=120

[Install]
WantedBy=multi-user.target
EOF

install -d -m 0755 "$(dirname "${DROPIN_PATH}")"
cat > "${DROPIN_PATH}" <<EOF
[Unit]
Requires=mail-storage.service
After=mail-storage.service
EOF

systemctl daemon-reload
systemctl enable mail-storage.service >/dev/null
if ! systemctl is-active --quiet mail-storage.service; then
  systemctl start mail-storage.service
fi
mountpoint -q "${MOUNT_PATH}" || die "${MOUNT_PATH} is not mounted"

install -d -m 0750 -o mail-server -g mail-server "${MOUNT_PATH}/data"

was_active=0
if systemctl is-active --quiet "${MAIL_SERVICE}.service"; then
  was_active=1
  systemctl stop "${MAIL_SERVICE}.service"
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
plaintext_backup="${MAIL_ROOT}/.plaintext-mail-migration-${timestamp}"
install -d -m 0700 "${plaintext_backup}"
declare -a migrated=()

rollback() {
  local rel source backup
  echo "encrypted-storage: migration failed; restoring plaintext paths" >&2
  systemctl stop "${MAIL_SERVICE}.service" 2>/dev/null || true
  for rel in "${migrated[@]}"; do
    source="${MAIL_ROOT}/${rel}"
    backup="${plaintext_backup}/${rel}"
    if [[ -L "${source}" && -e "${backup}" ]]; then
      unlink "${source}"
      install -d -m 0700 "$(dirname "${source}")"
      mv "${backup}" "${source}"
    fi
  done
  if [[ "${was_active}" -eq 1 ]]; then
    systemctl start "${MAIL_SERVICE}.service" 2>/dev/null || true
  fi
}
trap rollback ERR

declare -a paths=(mail dkim backups cert-backups mail.log)
while IFS= read -r candidate; do
  paths+=("$(basename "${candidate}")")
done < <(
  find "${MAIL_ROOT}" -maxdepth 1 -type f \
    \( -name 'smtp.db*' -o -name 'caldav.db*' -o -name 'forwards.json*' -o -name 'forwards.sieve*' \) \
    -print | sort
)

for rel in "${paths[@]}"; do
  source="${MAIL_ROOT}/${rel}"
  destination="${MOUNT_PATH}/data/${rel}"
  backup="${plaintext_backup}/${rel}"

  if [[ -L "${source}" ]]; then
    [[ "$(readlink "${source}")" == "${destination}" ]] \
      || die "${source} points somewhere other than encrypted storage"
    continue
  fi
  [[ -e "${source}" ]] || continue
  [[ ! -e "${destination}" ]] || die "${destination} already exists while ${source} is plaintext"

  install -d -m 0750 "$(dirname "${destination}")"
  cp -a "${source}" "${destination}.new"

  if [[ -d "${source}" ]]; then
    diff -qr "${source}" "${destination}.new" >/dev/null
  else
    cmp -s "${source}" "${destination}.new"
  fi

  mv "${source}" "${backup}"
  mv "${destination}.new" "${destination}"
  ln -s "${destination}" "${source}"
  migrated+=("${rel}")
done

if [[ -d "${MOUNT_PATH}/data/mail" ]]; then
  chown -R mail-server:mail-server "${MOUNT_PATH}/data/mail"
  find "${MOUNT_PATH}/data/mail" -type d -exec chmod 0700 {} +
  find "${MOUNT_PATH}/data/mail" -type f -exec chmod 0600 {} +
fi

for db in "${MOUNT_PATH}"/data/smtp.db* "${MOUNT_PATH}"/data/caldav.db*; do
  [[ -e "${db}" ]] || continue
  chown mail-server:mail-server "${db}"
  chmod 0600 "${db}"
done

if [[ -d "${MOUNT_PATH}/data/dkim" ]]; then
  chown -R mail-server:mail-server "${MOUNT_PATH}/data/dkim"
  find "${MOUNT_PATH}/data/dkim" -type d -exec chmod 0700 {} +
  find "${MOUNT_PATH}/data/dkim" -type f -exec chmod 0600 {} +
fi

for forwards in "${MOUNT_PATH}"/data/forwards.json* "${MOUNT_PATH}"/data/forwards.sieve*; do
  [[ -e "${forwards}" ]] || continue
  chown mail-server:mail-server "${forwards}"
  chmod 0600 "${forwards}"
done

if [[ -d "${MOUNT_PATH}/data/backups" ]]; then
  chown -R root:root "${MOUNT_PATH}/data/backups"
  find "${MOUNT_PATH}/data/backups" -type d -exec chmod 0700 {} +
  find "${MOUNT_PATH}/data/backups" -type f -exec chmod 0600 {} +
fi

if [[ -f /etc/mail/mail.env ]]; then
  chown root:root /etc/mail/mail.env
  chmod 0600 /etc/mail/mail.env
fi

sync

if systemctl list-unit-files "${MAIL_SERVICE}.service" --no-legend 2>/dev/null | grep -q "${MAIL_SERVICE}.service"; then
  systemctl start "${MAIL_SERVICE}.service"
  sleep 2
  systemctl is-active --quiet "${MAIL_SERVICE}.service" \
    || die "${MAIL_SERVICE}.service did not restart after migration"
fi

# The encrypted copy has been byte-checked and the service restarted from it.
# Remove the temporary plaintext rollback copy so message data is not left
# exposed beside the LUKS image.
find "${plaintext_backup}" -depth -delete
trap - ERR

echo "encrypted-storage: ready"
echo "encrypted-storage: image=${IMAGE_PATH}"
echo "encrypted-storage: mount=${MOUNT_PATH}"
echo "encrypted-storage: credential=${CREDENTIAL_PATH}"
if [[ "${created_image}" -eq 1 ]]; then
  echo "encrypted-storage: generated a new machine-bound volume key"
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${script_dir}/mail-storage-external.sh" ]]; then
  install -m 0700 "${script_dir}/mail-storage-external.sh" /usr/local/sbin/mail-storage-external
fi
