#!/usr/bin/env bash
# Remove fido2-ble-bridge. From the repository's linux/ directory:
#   sudo ./uninstall.sh [--purge]
# --purge also deletes /etc/fido2-ble-bridge (config and registered key mappings). The key stays
# paired with BlueZ either way; `bluetoothctl remove <address>` unpairs it.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "error: run as root: sudo $0" >&2; exit 1; }

if [[ -e /usr/share/pam-configs/fido2-ble-bridge ]]; then
  if command -v pam-auth-update >/dev/null; then
    pam-auth-update --package --remove fido2-ble-bridge
  fi
  rm -f /usr/share/pam-configs/fido2-ble-bridge
fi
if grep -rqs 'fido2-ble-bridge' /etc/pam.d; then
  echo "warning: /etc/pam.d still mentions fido2-ble-bridge; remove those lines by hand" >&2
fi
systemctl disable --now fido2-ble-bridge 2>/dev/null || true
rm -f /etc/systemd/system/fido2-ble-bridge.service
systemctl daemon-reload
rm -f /etc/dbus-1/system.d/fido2-ble-bridge.conf /etc/sysusers.d/fido2-ble-bridge.conf
busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig \
  >/dev/null 2>&1 || true
# The service user owns no files; remove it too.
userdel fido2-ble-bridge 2>/dev/null || true
rm -rf /opt/fido2-ble-bridge
rm -f /usr/local/bin/fido2-ble-bridge /etc/modules-load.d/fido2-ble-bridge.conf
if [[ ${1:-} == "--purge" ]]; then
  rm -rf /etc/fido2-ble-bridge
fi
echo "fido2-ble-bridge removed. The key is still paired with this computer's Bluetooth; to"
echo "unpair it: bluetoothctl remove <its address>"
