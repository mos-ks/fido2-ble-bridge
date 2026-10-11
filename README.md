# fido2-ble-bridge

Log in with a **Bluetooth LE FIDO2 security key** and its fingerprint sensor, with no cable.
The key stays a standard FIDO2 authenticator. Each platform gets a small component that lets
its own login stack use the key over Bluetooth LE.

| Platform | What it does | Guide |
| --- | --- | --- |
| Linux | A daemon that turns a bonded BLE key into a virtual USB FIDO key (kernel `uhid`), so `pam_u2f` and libfido2 work unchanged: desktop login, lock screen, `sudo` | [linux/README.md](linux/README.md) |
| Windows | `Fido2BleLogon`, a credential provider: a logon tile for local accounts, unlocked with the key's fingerprint | [windows/README.md](windows/README.md) |

## Linux

The bridge in [`linux/`](linux/README.md) is a Python service for systemd. It needs BlueZ
≥ 5.65, systemd ≥ 253, the `uhid` kernel module and a key that supports FIDO2 over BLE
(CTAP 2.1 section 11.4). It connects only to the one configured key, and only when BlueZ
reports that key as bonded, and it relays CTAP2 messages unchanged. To install it, run
`sudo ./install.sh` in `linux/`; its guided setup pairs the key, registers it for your account,
tests a login and then enables the key for logins. It asks before it installs packages, pairs or
uses a key (you type `yes` after seeing which device), removes or replaces a pairing or
registration, sets a PIN or enrolls a finger, gives the key's Bluetooth connections a longer
timeout (which restarts Bluetooth), and enables PAM, and at the end it lists every change with
its undo. At a login or `sudo`, a hint tells you to wake the key; the password prompt follows
only when the key fails or is not reached.

**Security.** The bridge is only a transport and cannot log anyone in. `pam_u2f` sends a fresh
challenge, the key signs it with a private key that never leaves the key, and `pam_u2f`
verifies the signature against the public key registered for the account. A compromised
bridge, a device spoofing the key's address or a radio attacker can make a login fail, not
succeed. The recommended setup requires the fingerprint (`userverification=1`). The shipped PAM
profile uses the key for the login and lock screens, and for `sudo` and the console's `login`
only when a check finds the request comes from your own session at this computer; never for
`sshd`, for `sudo` in an SSH session, or for `su` and polkit, which would let another user start
a login as you and make your key ask (polkit can be added behind the same check; see the Linux
guide). The service runs in a strict systemd sandbox. Other local
processes can still talk to a bonded key through BlueZ, as with any BLE key on Linux; each
signature still needs the fingerprint, and what the key signs for them cannot log anyone in.
[SECURITY.md](SECURITY.md) has the threat model and the hardening list.

## Windows

`Fido2BleLogon` in [`windows/`](windows/README.md) adds a sign-in option to the Windows logon and
lock screen for **local accounts** (Windows' own security-key sign-in only supports Entra ID
accounts). It needs Windows 10 version 2004 or later, a FIDO2 key with a fingerprint sensor that
works over Bluetooth LE and supports the `hmac-secret` and `credProtect` extensions, and the .NET 10
SDK. To install it, run `setup.cmd` in `windows/`: it builds and installs the tile, pairs the key,
enrolls your account (your Windows password, then two touches) and makes the tile the preselected
sign-in option. At the lock screen you press the key's button and touch the sensor.

**Security.** Unlike the Linux bridge, the tile signs in with your Windows password, which it
stores encrypted (AES-256-GCM) under a secret that the key releases only after verifying your
fingerprint (CTAP2 `hmac-secret` on a credential created with `credProtect` level 3). The tile
checks the key's signature against the enrolled credential, runs only on the logon and lock
screen, keeps its files admin-only and clears the password from memory right after use. The
key's PIN counts like a fingerprint, so use a strong key PIN and turn on device encryption.
[SECURITY.md](SECURITY.md#windows) has the threat model.

## Tested hardware

- **Linux:** confirmed on a Feitian AllinPass K33 with Ubuntu 24.04 (ARM64, BlueZ 5.72):
  pairing, registration, and fingerprint logins through `pam_u2f` at the login screen, for
  `sudo` and, with `polkit-1` added to the profile, for `pkexec`. The test suite also runs end
  to end through the real kernel (`uhid`, hidraw), libfido2, `pamu2fcfg` and `pam_u2f` with only
  the Bluetooth radio simulated. If you try another key, please report the model as described in
  [linux/README.md](linux/README.md#status).
- **Windows:** confirmed on a Feitian AllinPass K33 with Windows 11 (local account): pairing,
  enrollment and fingerprint sign-in on the real lock screen. The tile is also covered by an offline
  self-test that drives it the way LogonUI does, and the core by unit tests against a simulated
  authenticator; see [windows/README.md](windows/README.md).
- **Both:** one K33 can serve a Linux computer and a Windows computer: it keeps a pairing with
  each but connects to one at a time, so turn Bluetooth off on the computer you are not using.

## Reporting security issues

Privately, through GitHub's "Report a vulnerability" button; see [SECURITY.md](SECURITY.md).

## License

MIT; see [LICENSE](LICENSE).
