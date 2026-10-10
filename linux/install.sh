#!/usr/bin/env bash
# Install fido2-ble-bridge system-wide from this checkout, then run its guided setup. From the
# repository's linux/ directory:
#   sudo ./install.sh [--setup | --no-setup]
# Run from a terminal, it offers `fido2-ble-bridge setup` at the end (pair the key, register it,
# test it, enable it for logins). --setup runs it without asking, --no-setup skips it.
#
# The service runs exactly the files placed in /opt/fido2-ble-bridge (root-owned): a venv on the
# system Python with dependencies pinned by hash from uv.lock, plus this package's source.
set -euo pipefail

prefix=/opt/fido2-ble-bridge
config_dir=/etc/fido2-ble-bridge
unit_path=/etc/systemd/system/fido2-ble-bridge.service
launcher=/usr/local/bin/fido2-ble-bridge
pam_profile=/usr/share/pam-configs/fido2-ble-bridge
# Outside /usr/share/pam-configs on purpose: pam-auth-update reads every file there as a profile.
# The copy of the profile the last install shipped, to tell an admin's edit from an old version:
pam_profile_shipped="$config_dir/pam-profile.shipped"
# This version's profile, when an edited one was kept:
pam_profile_new="$config_dir/pam-profile.new"
placeholder="AA:BB:CC:DD:EE:FF"
project="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
packaging="$project/packaging"

die() { echo "error: $*" >&2; exit 1; }
warn() { echo "warning: $*" >&2; }

setup=ask
for arg in "$@"; do
  case $arg in
    --setup) setup=yes ;;
    --no-setup) setup=no ;;
    *) die "unknown option: $arg (expected --setup or --no-setup)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root: sudo $0"
/usr/bin/python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' \
  || die "needs /usr/bin/python3 >= 3.11"
/usr/bin/python3 -c 'import ensurepip' 2>/dev/null \
  || die "python3-venv is missing (Debian/Ubuntu: apt install python3-venv)"
command -v systemctl >/dev/null || die "systemd is missing"
# The sandboxed service gets /dev/uhid only through OpenFile= (systemd 253). Older systemd
# ignores that line, and the service would then fail and restart forever.
systemd_version="$(systemctl --version | awk 'NR == 1 { print $2 }')"
if [[ $systemd_version =~ ^[0-9]+$ ]] && ((systemd_version < 253)); then
  die "needs systemd >= 253 for OpenFile= (this system has $systemd_version)"
fi

modprobe uhid || die "cannot load the uhid kernel module, which the bridge needs (CONFIG_UHID)"
echo uhid > /etc/modules-load.d/fido2-ble-bridge.conf

# Build the new environment beside the old one, so a failed download leaves the running
# install untouched. The service only runs `python -m`, so moving the venv afterwards is safe.
staging="$prefix.new"
rm -rf "$staging"
/usr/bin/python3 -m venv "$staging"
"$staging/bin/python" -m pip install --quiet --disable-pip-version-check --no-deps \
  --require-hashes --only-binary=:all: -r "$packaging/requirements.txt"
site="$("$staging/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
cp -r "$project/src/fido2_ble_bridge" "$site/"
find "$site/fido2_ble_bridge" -name __pycache__ -prune -exec rm -rf {} +
"$staging/bin/python" -m compileall -q "$site/fido2_ble_bridge"
chown -R root:root "$staging"
chmod -R go-w "$staging"

if systemctl is-active --quiet fido2-ble-bridge; then
  systemctl stop fido2-ble-bridge
  restart=1
else
  restart=0
fi
rm -rf "$prefix.old"
if [[ -e $prefix ]]; then
  mv "$prefix" "$prefix.old"
fi
mv "$staging" "$prefix"
rm -rf "$prefix.old"

printf '#!/bin/sh\nexec %s/bin/python -I -m fido2_ble_bridge "$@"\n' "$prefix" > "$launcher"
chmod 0755 "$launcher"

install -d -m 0755 "$config_dir"
if [[ ! -e $config_dir/config.toml ]]; then
  install -m 0644 "$packaging/config.toml.example" "$config_dir/config.toml"
fi
install -m 0644 "$packaging/fido2-ble-bridge.service" "$unit_path"
profile_held=0
profile_updated=0
if [[ -d /usr/share/pam-configs ]]; then
  # The README has admins edit the installed profile's service list, and every later
  # pam-auth-update run applies what that file says. So, as dpkg does with a conffile, replace
  # the installed profile only while nobody changed it: when it is missing, already this
  # version's, or still the copy the last install shipped. An edited profile stays; when this
  # version ships a different one, that goes to pam-profile.new and the admin is warned.
  shipped_profile="$packaging/pam-configs/fido2-ble-bridge"
  if [[ ! -e $pam_profile ]] || cmp -s "$shipped_profile" "$pam_profile" \
    || { [[ -e $pam_profile_shipped ]] && cmp -s "$pam_profile_shipped" "$pam_profile"; }; then
    if [[ -e $pam_profile ]] && ! cmp -s "$shipped_profile" "$pam_profile"; then
      profile_updated=1
    fi
    install -m 0644 "$shipped_profile" "$pam_profile"
    rm -f "$pam_profile_new"
  elif [[ ! -e $pam_profile_shipped ]] || ! cmp -s "$shipped_profile" "$pam_profile_shipped"; then
    install -m 0644 "$shipped_profile" "$pam_profile_new"
    profile_held=1
  fi
  install -m 0644 "$shipped_profile" "$pam_profile_shipped"
fi
# An updated profile changes nothing until pam-auth-update writes it into common-auth, and a
# new version may change who can use the key. So where the profile is enabled, apply it now, as
# a Debian package's postinst would. pam-auth-update leaves a hand-edited common-auth alone.
profile_stale=0
if [[ $profile_updated -eq 1 ]] && command -v pam-auth-update >/dev/null \
  && grep -qs "pam_u2f\.so authfile=$config_dir/u2f_mappings" /etc/pam.d/common-auth; then
  DEBIAN_FRONTEND=noninteractive pam-auth-update --enable fido2-ble-bridge || true
  if ! grep -qs "fido2_ble_bridge\.local_session" /etc/pam.d/common-auth; then
    profile_stale=1
  fi
fi
systemctl daemon-reload

if grep -q "$placeholder" "$config_dir/config.toml"; then
  # No key configured yet: setup pairs one, writes its address and starts the service.
  echo "Installed."
else
  systemctl enable fido2-ble-bridge
  if [[ $restart -eq 1 ]] || ! systemctl is-active --quiet fido2-ble-bridge; then
    systemctl restart fido2-ble-bridge
  fi
  echo "Installed and running: systemctl status fido2-ble-bridge"
fi

missing=()
command -v bluetoothctl >/dev/null || missing+=(bluez)
command -v pamu2fcfg >/dev/null || missing+=(pamu2fcfg)
command -v fido2-token >/dev/null || missing+=(fido2-token)
pam_u2f_found=0
for candidate in /lib/*/security/pam_u2f.so /usr/lib/*/security/pam_u2f.so \
  /usr/lib/security/pam_u2f.so /usr/lib64/security/pam_u2f.so; do
  if [[ -e $candidate ]]; then
    pam_u2f_found=1
  fi
done
[[ $pam_u2f_found -eq 1 ]] || missing+=(pam_u2f.so)
if ((${#missing[@]} > 0)); then
  warn "not found yet: ${missing[*]}. Setup checks for them again and, on Debian and" \
    "Ubuntu, offers to install them (apt install bluez libpam-u2f pamu2fcfg fido2-tools)."
fi
if [[ $profile_held -eq 1 ]]; then
  # Last before the setup question, so that setup's output does not scroll it away unseen.
  warn "$pam_profile was changed on this system (its service list, for example), so it was" \
    "kept. This version's profile is in $pam_profile_new. The differences:"
  if command -v diff >/dev/null; then
    diff -u "$pam_profile" "$pam_profile_new" >&2 || true
  fi
  warn "merge what you need into $pam_profile, then run:" \
    "sudo pam-auth-update --enable fido2-ble-bridge. This version changes who may use the" \
    "key: su and polkit no longer do, and sudo uses it only in a session at this computer."
fi
if [[ $profile_stale -eq 1 ]]; then
  warn "/etc/pam.d/common-auth still has the previous version's lines for the key, which let" \
    "su, polkit and sudo in SSH sessions use it: pam-auth-update did not rewrite the file" \
    "(edited by hand?). Merge the new profile from $pam_profile into it, or run:" \
    "sudo pam-auth-update --enable fido2-ble-bridge"
fi

if [[ $setup == ask ]]; then
  setup=no
  if [[ -t 0 && -t 1 ]]; then
    read -r -p "Run the guided setup now (pair the key, register it, enable it)? [Y/n] " \
      answer || answer=n
    if [[ -z $answer || $answer == [Yy]* ]]; then
      setup=yes
    fi
  fi
elif [[ $setup == yes && ($profile_held -eq 1 || $profile_stale -eq 1) && -t 0 && -t 1 ]]; then
  # --setup asks nothing, so setup's output would scroll the warning away unseen.
  read -r -p "Press Enter to go on to the guided setup. " _ || true
fi
if [[ $setup == yes ]]; then
  echo
  exec "$launcher" setup
fi
echo "Next: sudo fido2-ble-bridge setup"
echo "It pairs the key, registers it for your account, tests it and enables it for logins, step"
echo "by step. See $project/README.md."
