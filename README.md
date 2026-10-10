# fido2-ble-bridge

Use a **Bluetooth LE FIDO2 security key** (for example one with a fingerprint sensor) on Linux
exactly like a USB key: desktop login, the lock screen, `sudo` and polkit through `pam_u2f`,
plus anything else built on libfido2. No cable, and no changes to `pam_u2f` or libfido2.

The Linux FIDO stack (libfido2, and with it `pam_u2f`, OpenSSH and systemd) only speaks USB HID
and NFC. This daemon gives a bonded BLE key a virtual USB FIDO device (via the kernel's `uhid`)
and relays CTAP2 messages between the two, unchanged.

```
pam_u2f / libfido2 ──► /dev/hidrawN (virtual, uhid) ──► fido2-ble-bridge ──► BlueZ ──► your key
                         CTAPHID, as for a USB key                 bonded, encrypted BLE link
```

## Security model

**The bridge cannot log anyone in.** It is a transport. `pam_u2f` sends a fresh random
challenge, the key signs it with a private key that never leaves the key, and `pam_u2f`
verifies that signature against the public key registered for your account. The bridge never
holds key material, so a compromised bridge, a spoofed Bluetooth device or a radio attacker can
only make a login fail. The end-to-end tests include exactly that case: a key that answers for
the right credential with the wrong private key is refused by the real `pam_u2f`.

On top of that:

- **Pinned, bonded key only.** The bridge connects only to the address in its config, and only
  if BlueZ reports it as paired *and* bonded. For bonded devices BlueZ requires link encryption
  with the stored long-term key as it connects (checked in BlueZ's `device.c`), so a device
  copying your key's address without that key cannot complete a connection. This is what
  CTAP 2.1 section 11.4 requires of BLE clients.
- **Fingerprint, not just presence.** The recommended PAM line uses `userverification=1`. The
  key must verify your fingerprint itself, so a stolen key alone does not get in.
- **CTAP2 only.** Legacy U2F messages, which cannot verify the user, are refused.
- **Strict, bounded parsing** of every HID report and BLE fragment. Message sizes are capped at
  the protocol maxima, the notification queue is bounded, and a malformed stream drops the link.
- **Nothing sensitive in the logs.** Message contents are never logged, only events and sizes.
- **Sandboxed service.** It runs as a throwaway `DynamicUser` with no capabilities, no network
  (D-Bus only), a read-only filesystem, a private `/dev` holding only `/dev/uhid`, and a
  system-call filter. See `packaging/fido2-ble-bridge.service`.
- **Pinned dependencies.** The installer installs runtime dependencies (`bleak`, `dbus-fast`)
  from binary wheels only, verified against hashes from `uv.lock`.

What it does **not** protect against: root on this machine (root can drive the key through the
bridge or BlueZ directly, as it could drive a USB key); someone holding your key *and* your
finger; relaying your key's radio from a distance while you touch it; or radio jamming, which
only makes the login fall back to your password. Bluetooth pairing is system-wide, so any local
root process can talk to the bonded key: the "system-wide pairing" caveat in CTAP 2.1
section 11.4.13.1. See [SECURITY.md](SECURITY.md).

## Requirements

- Linux with BlueZ ≥ 5.65 (it must report `Bonded`) and the `uhid` kernel module (standard on
  Debian 12+, Ubuntu 24.04+, Fedora, Arch)
- Python ≥ 3.11 with `venv` (`apt install python3-venv` on Debian/Ubuntu)
- `pam_u2f` ≥ 1.1 and libfido2 tools: `apt install libpam-u2f pamu2fcfg fido2-tools`
- A FIDO2 key that supports the BLE transport (CTAP 2.1 section 11.4)

## Setup

### 1. Pair the key with BlueZ

Put the key in Bluetooth pairing mode (see its manual), then:

```console
$ bluetoothctl
[bluetooth]# agent KeyboardDisplay
[bluetooth]# default-agent
[bluetooth]# scan le
[bluetooth]# pair AA:BB:CC:DD:EE:FF        # type the passkey if the key asks for one
[bluetooth]# trust AA:BB:CC:DD:EE:FF
[bluetooth]# info AA:BB:CC:DD:EE:FF        # expect "Paired: yes" and "Bonded: yes"
```

Pair somewhere private: pairing is the moment an attacker nearby could get in the middle.
`fido2-ble-bridge scan` (after step 2) lists nearby keys that advertise FIDO over BLE.

### 2. Install

```console
$ git clone https://github.com/mos-ks/fido2-ble-bridge
$ cd fido2-ble-bridge
$ sudo ./packaging/install.sh
```

This loads `uhid` at boot, creates `/opt/fido2-ble-bridge`, installs the systemd unit and the
`fido2-ble-bridge` command, and writes `/etc/fido2-ble-bridge/config.toml` on first install.
It does not touch your PAM configuration.

### 3. Configure and check

Set your key's address in `/etc/fido2-ble-bridge/config.toml`, then wake the key and run:

```console
$ fido2-ble-bridge check
Waiting up to 10s for AA:BB:CC:DD:EE:FF: wake the key now.
OK: bonded and encrypted link, FIDO2 selected, fragment size …, getInfo returned … bytes.
$ sudo systemctl enable --now fido2-ble-bridge
$ fido2-token -L                     # the bridge shows up as a USB FIDO device
/dev/hidraw5: vendor=0x0000, product=0x0000 ( )
$ fido2-token -I /dev/hidraw5        # with the key awake: its real getInfo
```

### 4. Fingerprint

If the key has no fingerprint enrolled yet, you can enroll one through the bridge. A PIN must
be set first:

```console
$ fido2-token -S /dev/hidraw5          # set a PIN, if none is set
$ fido2-token -S -e /dev/hidraw5       # enroll a fingerprint (touch the sensor repeatedly)
```

`fido2-token -I` should then list `uv` among the options. The vendor's own app works too.

### 5. Register the key for your account

With the key awake:

```console
$ pamu2fcfg -u "$USER" -o pam://fido2-ble-bridge -i pam://fido2-ble-bridge -V \
    | sudo tee /etc/fido2-ble-bridge/u2f_mappings
```

`-V` makes the fingerprint mandatory for this credential. For more users, append one line per
user. To add a backup key to the same user, append the output of `pamu2fcfg -n …` to that user's
line.

### 6. Test, then enable PAM

Keep a root shell open until you have tested a fresh login, so a mistake cannot lock you out.

```console
$ sudo apt install pamtester
$ echo 'auth required pam_u2f.so authfile=/etc/fido2-ble-bridge/u2f_mappings origin=pam://fido2-ble-bridge cue userverification=1' \
    | sudo tee /etc/pam.d/fido2-ble-test
$ pamtester fido2-ble-test "$USER" authenticate      # wake the key, touch the sensor
pamtester: successfully authenticated
$ sudo rm /etc/pam.d/fido2-ble-test
$ sudo pam-auth-update --enable fido2-ble-bridge
```

This adds the key in front of your password for every service that uses `common-auth`: the
display manager, the lock screen, `sudo`, `su`, polkit and console login. If the key is absent
or fails, you get the password prompt as before. To undo: `sudo pam-auth-update --disable
fido2-ble-bridge`.

## Using it

At a login prompt, wake the key (before or after starting the login). The bridge waits up to
`connect_timeout` seconds for it, then `pam_u2f` shows "Please touch the device." and you touch
the sensor. If the key does not appear in time, you get the password prompt.

- **Wait time without the key.** When you log in without the key nearby, each prompt first waits
  `connect_timeout` seconds. Lower it in the config if that bothers you.
- **GNOME keyring.** The login keyring is encrypted with your password, so after a passwordless
  login GNOME asks for that password the first time something needs the keyring. This is a
  general consequence of passwordless login, not specific to this bridge.
- **Browsers.** Chrome and Firefox look for security keys on hidraw, so they should find the
  bridge for WebAuthn too. This is untested.

## Configuration

`/etc/fido2-ble-bridge/config.toml`; unknown keys are rejected.

| Key | Default | Meaning |
| --- | --- | --- |
| `address` | (required) | Bluetooth address of the bonded key |
| `adapter` | system default | Bluetooth adapter, e.g. `hci1` |
| `connect_timeout` | `10` | Seconds a request waits for the key to connect (1 to 120) |
| `request_timeout` | `60` | Further seconds one request may take, fingerprint wait included (5 to 300) |
| `idle_disconnect` | `10` | Seconds the link stays open after the last request (0 to 600) |
| `device_name` | `FIDO2 BLE bridge` | Name of the virtual HID device |

## Troubleshooting

- `journalctl -u fido2-ble-bridge -f` shows connections, timeouts and refusals.
- `check` says **not bonded**: pair and trust the key again (step 1); `info` must show
  `Bonded: yes`.
- `check` says **does not offer FIDO2 over BLE**: the key has no FIDO2 BLE service, or only
  legacy U2F over BLE, which this bridge does not support.
- `check` times out: wake the key and make sure it is not connected to another device (a
  phone, for example).
- `pamu2fcfg` registers the wrong key: it uses the first FIDO device it finds, so unplug other
  security keys while registering.

## Status

Verified by the test suite: the CTAPHID and FIDO-BLE framing against the CTAP 2.1 spec
examples; the BLE link against a simulated authenticator (handshake, fragmentation with
sequence wraparound, keepalives, cancel, disconnects, timeouts, refusal of unbonded or
non-FIDO2 devices); and end to end through the real kernel (`uhid`, hidraw), libfido2's
`fido2-token`, `pamu2fcfg` and `pam_u2f` with only the radio simulated. That includes a full
fingerprint login and its refusal on a failed fingerprint or a wrong signature.

**Not yet confirmed on physical BLE keys.** If you try it, please open an issue with the key
model and the output of `fido2-ble-bridge check`, so this section can list keys that work.

## Development

```console
$ uv sync
$ uv run pytest            # unit, link and bridge tests
$ uv run ruff check . && uv run ruff format --check . && uv run mypy
```

The end-to-end tests in `tests/test_e2e_uhid.py` run when `/dev/uhid` is writable (it is for
the logged-in user on most desktops) and `fido2-token`, `pamu2fcfg` and `pam_u2f.so` are
installed. Point `FIDO2_TOKEN`, `PAMU2FCFG` and `PAM_U2F_SO` at other builds if needed. They
use `pam_start_confdir`, so they never touch `/etc/pam.d`. CI runs them on every push.

## License

MIT
