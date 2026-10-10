#!/usr/bin/env bash
# Install fido2-ble-bridge system-wide from this checkout: sudo ./packaging/install.sh
#
# The service runs exactly the files placed in /opt/fido2-ble-bridge (root-owned): a venv on the
# system Python with dependencies pinned by hash from uv.lock, plus this package's source.
set -euo pipefail

prefix=/opt/fido2-ble-bridge
config_dir=/etc/fido2-ble-bridge
unit_path=/etc/systemd/system/fido2-ble-bridge.service
launcher=/usr/local/bin/fido2-ble-bridge
pam_profile=/usr/share/pam-configs/fido2-ble-bridge
placeholder="AA:BB:CC:DD:EE:FF"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(dirname "$here")"

die() { echo "error: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root: sudo $0"
/usr/bin/python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' \
  || die "needs /usr/bin/python3 >= 3.11"
/usr/bin/python3 -c 'import ensurepip' 2>/dev/null \
  || die "python3-venv is missing (Debian/Ubuntu: apt install python3-venv)"
command -v bluetoothctl >/dev/null || die "BlueZ is missing (apt install bluez)"

echo uhid > /etc/modules-load.d/fido2-ble-bridge.conf
modprobe uhid

if systemctl is-active --quiet fido2-ble-bridge; then
  systemctl stop fido2-ble-bridge
  restart=1
else
  restart=0
fi

/usr/bin/python3 -m venv --clear "$prefix"
"$prefix/bin/python" -m pip install --quiet --disable-pip-version-check --no-deps \
  --require-hashes --only-binary=:all: -r "$here/requirements.txt"
site="$("$prefix/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
cp -r "$repo/src/fido2_ble_bridge" "$site/"
find "$site/fido2_ble_bridge" -name __pycache__ -prune -exec rm -rf {} +
"$prefix/bin/python" -m compileall -q "$site/fido2_ble_bridge"
chown -R root:root "$prefix"
chmod -R go-w "$prefix"

printf '#!/bin/sh\nexec %s/bin/python -I -m fido2_ble_bridge "$@"\n' "$prefix" > "$launcher"
chmod 0755 "$launcher"

install -d -m 0755 "$config_dir"
if [[ ! -e $config_dir/config.toml ]]; then
  install -m 0644 "$here/config.toml.example" "$config_dir/config.toml"
fi
install -m 0644 "$here/fido2-ble-bridge.service" "$unit_path"
install -m 0644 "$here/pam-configs/fido2-ble-bridge" "$pam_profile"
systemctl daemon-reload

if grep -q "$placeholder" "$config_dir/config.toml"; then
  echo "Installed. Next: set your key's address in $config_dir/config.toml, then"
  echo "  fido2-ble-bridge check && sudo systemctl enable --now fido2-ble-bridge"
else
  systemctl enable fido2-ble-bridge
  if [[ $restart -eq 1 ]] || ! systemctl is-active --quiet fido2-ble-bridge; then
    systemctl restart fido2-ble-bridge
  fi
  echo "Installed and running: systemctl status fido2-ble-bridge"
fi
echo "PAM is NOT enabled yet; see the README (pamu2fcfg, then pam-auth-update)."
