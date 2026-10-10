#!/usr/bin/env bash
# Remove fido2-ble-bridge: sudo ./packaging/uninstall.sh [--purge]
# --purge also deletes /etc/fido2-ble-bridge (config and registered key mappings).
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "error: run as root: sudo $0" >&2; exit 1; }

if [[ -e /usr/share/pam-configs/fido2-ble-bridge ]]; then
  pam-auth-update --package --remove fido2-ble-bridge
  rm -f /usr/share/pam-configs/fido2-ble-bridge
fi
systemctl disable --now fido2-ble-bridge 2>/dev/null || true
rm -f /etc/systemd/system/fido2-ble-bridge.service
systemctl daemon-reload
rm -rf /opt/fido2-ble-bridge
rm -f /usr/local/bin/fido2-ble-bridge /etc/modules-load.d/fido2-ble-bridge.conf
if [[ ${1:-} == "--purge" ]]; then
  rm -rf /etc/fido2-ble-bridge
fi
echo "fido2-ble-bridge removed."
