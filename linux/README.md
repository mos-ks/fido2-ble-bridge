# fido2-ble-bridge for Linux

Use a **Bluetooth LE FIDO2 security key** (for example one with a fingerprint sensor) on Linux
exactly like a USB key: desktop login, the lock screen and `sudo` through `pam_u2f`, plus
anything else built on libfido2. No cable, and no changes to `pam_u2f` or libfido2.

The Linux FIDO stack (libfido2, and with it `pam_u2f`, OpenSSH and systemd) only speaks USB HID
and NFC. This daemon gives a bonded BLE key a virtual USB FIDO device (via the kernel's `uhid`)
and relays CTAP2 messages between the two, unchanged.

```
pam_u2f / libfido2 ──► /dev/hidrawN (virtual, uhid) ──► fido2-ble-bridge ──► BlueZ ──► your key
                         CTAPHID, as for a USB key                 bonded, encrypted BLE link
```

## Quick start

You need Ubuntu 24.04 or newer, Debian 13 or newer, or a similarly recent distribution (see
[Requirements](#requirements)), and a FIDO2 key that works over Bluetooth LE. Have the key
charged and at hand, and enroll a fingerprint on it first if you can (setup can also do that).
The installer needs git and Python 3.11 or newer with `venv`; setup offers the rest.

```console
$ sudo apt install git python3-venv        # Debian and Ubuntu
$ git clone https://github.com/mos-ks/fido2-ble-bridge
$ cd fido2-ble-bridge/linux
$ sudo ./install.sh
```

The installer sets up the service, then asks whether to run the guided setup. Answer yes (or
run `sudo fido2-ble-bridge setup` yourself later) and follow the prompts. When setup asks for
it, put the key in **pairing mode**: on many keys you hold the button for about 5 seconds until
the LED blinks fast; a short press only wakes the key. Wait for the prompt, because most keys
leave pairing mode again after a minute or two.

Setup goes through eight steps. Each one checks first and skips what is already done, so you
can stop at any point (Ctrl-C) and run it again:

1. **Prerequisites.** BlueZ 5.65 or newer, systemd 253 or newer, the `uhid` module, `pam_u2f`,
   `pamu2fcfg` and `fido2-token`. On Debian and Ubuntu it offers to install missing packages
   with `apt-get`; elsewhere it names them.
2. **Pairing.** It looks for keys in pairing mode, shows the one it found (or lets you pick one
   if there are several) and pairs it only once you type `yes`: any device nearby can claim to
   be a FIDO key, even with your key's address, so pair somewhere private. It then pairs and
   bonds the key with BlueZ and marks it trusted. If the key asks for a passkey, you type it in
   the terminal. A device BlueZ already has a bond with is also used only after you typed
   `yes`, because any local user can pair one. If the key in the configuration has lost its
   pairing, setup warns before it pairs anything (see
   [the security model](#security-model)). An existing pairing is only removed after you agree.
3. **Configuration.** It writes the key's address into `/etc/fido2-ble-bridge/config.toml`,
   keeping your other settings and comments. On a computer with several Bluetooth adapters it
   also writes the one the key is bonded on. Then, after asking, it gives the key's
   connections a 20 ms interval instead of Linux's 30 to 50 ms, which makes a login faster, and
   lets them go 5 seconds without radio contact instead of 0.42 s, in BlueZ's settings for the
   key (the `[ConnectionParameters]` group of `/var/lib/bluetooth/<adapter>/<key>/info`), and
   restarts Bluetooth so that BlueZ loads them. It keeps values the key itself asked for.
4. **Service.** It enables and starts the bridge, then checks the key over Bluetooth. Wake the
   key when asked (a short press).
5. **Fingerprint.** It finds the bridge's virtual device (by its name, bus and `phys`, and only
   if libfido2 lists it as a FIDO device), then checks through it that the key has a
   fingerprint enrolled, and otherwise offers to enroll one (`fido2-token -S -e`, which needs the
   key's PIN; it offers to set a PIN first if the key has none).
6. **Registration.** It runs `pamu2fcfg` once for your account: touch the sensor when the key
   lights up. It must be your own key that lights up and reads your finger; if setup moves on
   without that, press Ctrl-C. It can also register a backup key that has its own fingerprint
   sensor, plugged in over USB (the PAM line requires the key to verify a fingerprint itself,
   so a PIN-only key could not log in).
7. **Test.** One real login through `pam_u2f` with a temporary PAM configuration outside
   `/etc/pam.d`, with the installed PAM profile's own `pam_u2f` line, on exactly the
   `/etc/fido2-ble-bridge/u2f_mappings` content it will save, and with no other FIDO device
   plugged in: touch the sensor once more. Only when it passes does setup save the
   registration. A new registration replaces all of your account's lines in that file
   (`pam_u2f` only reads the last one), and a backup key goes on the line that counts.
8. **Enable.** Only after the test passed, and only once you type `yes`, it enables the PAM
   profile with `pam-auth-update` (Debian and Ubuntu). Elsewhere it prints the lines to add.
   It refuses a profile whose `pam_u2f` line was weakened (no `userverification=1`, or
   `alwaysok`, `nouserok`, `openasuser`, `expand` or options it does not know) or changed
   since the test.

At the end it lists everything it changed and how to undo each change.

Before you type `yes` in step 8, open a root shell in a second terminal (`sudo -i`) and keep it
open until a fresh `sudo -k; sudo true` and the lock screen work with the key. If anything goes
wrong, that shell lets you undo it: `pam-auth-update --disable fido2-ble-bridge`.

**Fingerprint attempts.** Setup asks the key for your fingerprint at most twice (registration
and test) and never retries on its own. Some keys lock or reset themselves after a number of
failed matches in a row, so if your finger is not recognised, check which finger is enrolled
before you run setup again.

Options: `sudo fido2-ble-bridge setup [--user NAME] [--address AA:BB:CC:DD:EE:FF] [--yes]
[--no-pam]`. Setup is for the account that ran `sudo` unless you name another with `--user`
(root only with `--user root`). `--address` selects that key: if BlueZ already has a bond with
it (for example one copied from Windows), setup skips pairing; otherwise it waits for that key
alone in pairing mode. Either way it shows the device but does not ask you to type `yes`, since
you named it. `--yes` installs missing packages without asking, and `--no-pam` does everything
except step 8.
`sudo ./install.sh --setup` runs setup without asking, and `--no-setup` skips it.

### Undoing it

| Change | Undo |
| --- | --- |
| Key paired with BlueZ | `bluetoothctl remove AA:BB:CC:DD:EE:FF` |
| Key used for logins (PAM) | `sudo pam-auth-update --disable fido2-ble-bridge` |
| Service enabled | `sudo systemctl disable --now fido2-ble-bridge` |
| Key registered for an account | delete the account's line from `/etc/fido2-ble-bridge/u2f_mappings` (when setup changed an existing line, the file as it was is kept in `u2f_mappings.bak`) |
| Packages installed by setup | `sudo apt-get remove …`, as setup's summary lists them |
| Everything the installer added | `sudo ./uninstall.sh` (`--purge` also deletes `/etc/fido2-ble-bridge`) |

## Security model

**The bridge cannot log anyone in.** It is a transport. `pam_u2f` sends a fresh random
challenge, the key signs it with a private key that never leaves the key, and `pam_u2f`
verifies that signature against the public key registered for your account. The bridge never
holds key material, so a compromised bridge, a spoofed Bluetooth device or a radio attacker can
only make a login fail. The end-to-end tests include exactly that case: a key that answers for
the right credential with the wrong private key is refused by the real `pam_u2f`.

On top of that:

- **Pinned, bonded key only.** The bridge connects only to the address in its config, and only
  if BlueZ reports it as paired *and* bonded. For a device bonded over LE, which is how FIDO
  keys pair, BlueZ requires link encryption with the stored long-term key as it connects
  (checked in BlueZ's `device.c`). So a device copying your key's address without that key
  cannot complete a connection, as CTAP 2.1 section 11.4 requires. Newer BlueZ reports the LE
  bond separately and the bridge checks that too. On older BlueZ (5.72 in Ubuntu 24.04) a bond
  made over classic Bluetooth would also pass, which only matters if the configured address
  belongs to a dual-mode device rather than your key.
- **Who can start a login that asks your key.** The shipped PAM profile uses
  the key for the login screen and lock screens (GDM, SDDM, LightDM and common screen lockers),
  and for `sudo`, `sudo -i` and the text console's `login`, these three only after a check
  (`fido2_ble_bridge.local_session`, run through `pam_exec`) has asked logind where the request
  comes from. The check lets the key be used only for a session at this computer's seat that
  belongs to the account being logged in, and skips the key whenever it cannot tell. In detail:
  - **You, at this computer**, get the key at the login screen, the lock screen, the console's
    `login` (on a virtual console) and for `sudo` in your terminals. GNOME and KDE start
    terminals outside the login session; for those, the check goes by your graphical session,
    as polkit does: it must be at this computer and active, and none of your login sessions
    may be remote, so while you are also logged in over SSH, `sudo` asks for your password.
  - **Anyone logged in over SSH**, you included, gets the password prompt: `sshd` does not use
    the key, and `sudo` in an SSH session (or any session without a seat, such as xrdp) skips
    it.
  - **Other users of this computer**, at the console or over SSH, cannot start a login as you
    that asks your key: `su` and polkit (`pkexec`, the desktop's administrator dialogs), which
    let the caller name the account to log in as, are not in the profile and ask for your
    password, and `sudo` only ever logs in the account that runs it. They can still make the
    key itself ask for a fingerprint by talking to it through BlueZ (see below), but what it
    signs for them cannot log anyone in, because `pam_u2f` checks a challenge of its own.
  - **Programs running as you** can run `sudo` and make the key ask, as with a USB key. That
    includes someone who has your account, for example through a stolen SSH key: they can
    start `sudo` in a way that looks local (through your systemd user instance, say). Touch
    the key only when you started a login yourself.

  To add `polkit-1` (or another service), see [Manual setup](#5-test-then-enable-pam).
- **Fingerprint, not just presence.** Setup registers the key with `pamu2fcfg -V` and the PAM
  line uses `userverification=1`. The key must verify your fingerprint itself, so a stolen key
  alone does not get in.
- **CTAP2 only.** Legacy U2F messages, which cannot verify the user, are refused.
- **Strict, bounded parsing** of every HID report and BLE fragment. Message sizes are capped at
  the protocol maxima, the notification queue is bounded, and a malformed stream drops the link.
- **Nothing sensitive in the logs.** The bridge never logs message contents, and `-v` leaves the
  payload-level debug output of `bleak` and `dbus-fast` switched off.
- **Bounded in time.** Every request has a hard deadline (`connect_timeout` plus
  `request_timeout`, counted from the start of the request), so a misbehaving key or Bluetooth
  stack cannot hang a login prompt.
- **No request reaches the key twice.** A link kept open between requests can die unnoticed.
  The bridge then sends nothing again but getInfo, which changes nothing on the key, and only
  when the key acknowledged none of it. Before any other request on a link that sat idle for
  over a second, it checks the link with a BLE PING carrying a random payload, and reconnects
  if the echo does not come back within a second. So a lost write response cannot make the key
  run a PIN change twice (costing a PIN retry) or ask for your fingerprint twice.
- **Sandboxed service.** It runs as a dedicated unprivileged system user (`fido2-ble-bridge`) with no capabilities, no network
  (D-Bus only), a read-only filesystem, a private `/dev` without physical devices, and a
  system-call filter.
  systemd opens the root-only `/dev/uhid` and passes the service just that file descriptor
  (`OpenFile=`), so no device permissions or groups are loosened. See
  `packaging/fido2-ble-bridge.service`.
- **Pinned dependencies.** The installer installs runtime dependencies (`bleak`, `dbus-fast`)
  from binary wheels only, verified against hashes from `uv.lock`.
- **A careful setup.** Setup pairs or uses only a device it showed you and you confirmed by
  typing `yes` (or named with `--address`), with its own short-lived BlueZ agent, which answers
  only for the key being paired and is never made the default agent, so the desktop's agent is
  left alone. It warns when the configured key has lost its pairing. It prints device names,
  which anyone nearby can choose, only as plain text. It sends nothing to the bridge's virtual
  device before libfido2 lists it, and never takes a Bluetooth keyboard's device of the same
  name for it. It saves a registration only after a login with exactly that registration and
  the profile's own `pam_u2f` line worked, tests the PAM line outside `/etc/pam.d` before
  enabling anything, refuses a weakened profile, never edits PAM files itself (only
  `pam-auth-update` does, never with `--force`), never writes a config that fails validation,
  and never logs passkeys or registration data. When it sets the key's connection timing, it
  changes only the `[ConnectionParameters]` group of BlueZ's settings file for the
  key, reads that file exactly as GLib does (so a device name or alias that another local user
  chose cannot make it split a line), and refuses any edit that would change another line,
  the bond's keys among them.

What it does **not** protect against:

- **Other local processes using the key through BlueZ.** Bluetooth pairing is system-wide, and
  BlueZ's default D-Bus policy lets any local user talk to a bonded device. So any process on
  this machine can connect to your key directly and ask it to sign. Each signature still needs
  your fingerprint on the key. This is the "system-wide pairing" caveat of CTAP 2.1 section
  11.4.13.1 and applies to every BLE security key on Linux. To close it, [restrict BlueZ to
  the `bluetooth` group](#restricting-bluez-to-the-bluetooth-group).
- **A local user replacing your key's pairing.** The same policy lets any local user remove a
  pairing, and pair a device of their own. The bridge then either stops working or connects
  to whatever is bonded at the configured address, which can make logins fail but not succeed:
  it cannot sign for your registered credential. The danger is the next setup run, which would
  register that device for your account. Setup therefore warns when the configured key has
  lost its pairing, and uses or pairs a device only after you saw it and typed `yes`. Run setup
  with the key in your hand, and if the pairing vanished without you removing it, find out why
  first. Restricting BlueZ to the `bluetooth` group closes this too.
- **A device that is not a genuine key.** Setup does not check the key's attestation
  certificate, so it cannot prove that the paired device is a genuine key of its vendor: it
  relies on you confirming the device, and on the key lighting up and reading your finger
  during registration and the login test.
- **Root on this machine**, which can drive the key as it could a USB key.
- **Someone with your key and your finger.**
- **Relay attacks**, which forward your key's radio from a distance while you touch it.
- **Radio jamming**, which only makes the login fall back to your password.
- **A nearby attacker during pairing.** Pairing is the moment someone close by could get in the
  middle, so pair somewhere private.

The virtual hidraw node itself is reachable only by root and the logged-in desktop user, through
systemd's standard FIDO udev rules (`60-fido-id.rules` with `uaccess`). See
[SECURITY.md](../SECURITY.md).

### Restricting BlueZ to the bluetooth group

BlueZ's own D-Bus policy lets every local user use Bluetooth: talk to your key, remove its
pairing, pair devices of their own. On a computer with users you do not trust, you can limit
that to root and the members of the `bluetooth` group. The cost: accounts outside the group lose
Bluetooth entirely, the desktop's Bluetooth settings and Bluetooth headphones included, so add
every account that should keep it. Setup does not do this for you.

```console
$ getent group bluetooth || sudo groupadd --system bluetooth
$ sudo usermod -aG bluetooth alice        # each account that keeps Bluetooth; then log out and in
$ sudo systemctl edit fido2-ble-bridge    # the bridge's service needs the group too; add:
```

```ini
[Service]
SupplementaryGroups=bluetooth
```

Then save this as `/etc/dbus-1/system.d/zz-fido2-ble-bridge-bluez.conf`. D-Bus reads
`/etc/dbus-1/system.d` after `/usr/share/dbus-1/system.d`, where BlueZ puts its own
`bluetooth.conf`, and the `zz-` prefix sorts it last, so its rules override BlueZ's default
ones (rules for other groups that BlueZ's file names, such as `lp` on some distributions,
still apply to their members):

```xml
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <!-- Only root and the bluetooth group may use BlueZ (fido2-ble-bridge README). -->
  <policy context="default">
    <deny send_destination="org.bluez"/>
  </policy>
  <policy group="bluetooth">
    <allow send_destination="org.bluez"/>
  </policy>
</busconfig>
```

```console
$ sudo systemctl reload dbus
$ sudo systemctl restart fido2-ble-bridge
$ sudo -u nobody busctl call org.bluez / org.freedesktop.DBus.ObjectManager GetManagedObjects
Call failed: Access denied ...                       # outside the group: refused
```

Wake the key and run `fido2-token -I /dev/hidrawN` on the bridge's device to see that the bridge
still reaches it. To undo, delete the file and run `sudo systemctl reload dbus`.

## Requirements

- Linux with BlueZ ≥ 5.65 (it must report `Bonded`), systemd ≥ 253 (for `OpenFile=`) and the
  `uhid` kernel module: Ubuntu 24.04+, Debian 13+, current Fedora and Arch
- Python ≥ 3.11 with `venv` (`apt install python3-venv` on Debian/Ubuntu)
- `pam_u2f` ≥ 1.1 and libfido2 tools: `apt install libpam-u2f pamu2fcfg fido2-tools` (setup
  offers this on Debian and Ubuntu)
- Linux-PAM ≥ 1.4 for setup's login test (`pam_start_confdir`); older systems test by hand
- A FIDO2 key that supports the BLE transport (CTAP 2.1 section 11.4)

## Manual setup

What `fido2-ble-bridge setup` does, as individual commands, for systems where you prefer to do
it by hand. Install without the guided setup first:

```console
$ git clone https://github.com/mos-ks/fido2-ble-bridge
$ cd fido2-ble-bridge/linux
$ sudo ./install.sh --no-setup
```

This loads `uhid` at boot, creates `/opt/fido2-ble-bridge`, installs the systemd unit and the
`fido2-ble-bridge` command, and writes `/etc/fido2-ble-bridge/config.toml` on first install.
It does not touch your PAM configuration.

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
`fido2-ble-bridge scan` lists nearby keys that advertise FIDO over BLE.

### 2. Configure and check

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

Linux talks to a Bluetooth LE device every 30 to 50 ms (the controller picks near 50), and a
login needs some thirty exchanges with the key, each about two intervals long. It also ends a
connection after 0.42 s without radio contact, so a key that pauses longer, busy or a few
metres away, drops a login midway. BlueZ loads other values for one device from its settings
file when it starts. Add this group to the key's file (or change the values, if the file has
the group already):

```ini
[ConnectionParameters]
MinInterval=16
MaxInterval=16
Latency=0
Timeout=500
```

```console
$ sudo ls /var/lib/bluetooth/        # your adapter's address
$ sudoedit /var/lib/bluetooth/<adapter>/AA:BB:CC:DD:EE:FF/info
$ sudo systemctl restart bluetooth   # Bluetooth devices reconnect by themselves
```

That is a 20 ms interval (units of 1.25 ms) and a 5 s timeout (units of 10 ms). Do not go below
the key's own minimum: a key offered less asks for its own values, and BlueZ then stores those
over yours (a Feitian AllinPass K33 asks for 20 to 50 ms and a 4 s timeout). BlueZ keeps the
group until the pairing is removed, or until the key asks for parameters of its own.

### 3. Fingerprint

If the key has no fingerprint enrolled yet, you can enroll one through the bridge. A PIN must
be set first:

```console
$ fido2-token -S /dev/hidraw5          # set a PIN, if none is set
$ fido2-token -S -e /dev/hidraw5       # enroll a fingerprint (touch the sensor repeatedly)
```

`fido2-token -I` should then list `uv` among the options. The vendor's own app works too.

### 4. Register the key for your account

With the key awake, and no other FIDO key plugged in (`pamu2fcfg` uses the first one it finds):

```console
$ line=$(pamu2fcfg -u "$USER" -o pam://fido2-ble-bridge -i pam://fido2-ble-bridge -V) \
    && printf '%s\n' "$line" | sudo tee /etc/fido2-ble-bridge/u2f_mappings
```

`-V` makes the fingerprint mandatory for this credential. The file is written only when
`pamu2fcfg` succeeded, so a failed attempt (finger not recognised, key asleep) leaves it as it
was; piping `pamu2fcfg` straight into `tee` would empty it first. `tee` replaces the file, so
for each further user append their line instead (the same command with `sudo tee -a`). Keep one
line per user: `pam_u2f` reads only the last line of a user, so appending a second line for
the same user silently replaces the first. To add a backup key to the same user, append the
output of `pamu2fcfg -n …` to the end of that user's line. The backup key needs its own
fingerprint sensor: the PAM line requires the key to verify a fingerprint itself, so a PIN-only
key could not log in.

### 5. Test, then enable PAM

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

This puts the key in front of your password in `common-auth`, for two kinds of PAM services.
The profile `/usr/share/pam-configs/fido2-ble-bridge` has two `service in …` lists:

- The **first** list names every service that may use the key: `gdm-password` (GNOME login and
  lock screen), `sddm`, `kde`, `lightdm`, common screen lockers, `sudo`, `sudo-i` and `login`.
  Every other service, `sshd`, `su` and `polkit-1` included, skips the key and asks for the
  password as before.
- The **second** list names the login and lock screens, which only someone at this computer can
  use. All other services in the first list (`sudo`, `sudo-i`, `login`) first run the local
  session check, `pam_exec.so quiet /opt/fido2-ble-bridge/bin/python -I -m
  fido2_ble_bridge.local_session`, and use the key only when it exits 0: when the request comes
  from a session of the account being logged in that is at this computer's seat and not remote
  (details in [Security model](#security-model)). When the check fails, or cannot run, the key is
  skipped and you get the password prompt; each skip leaves a `pam_exec(…): … failed: exit code
  1` line in the journal. To see why it skips the key for you, run it as `pam_exec` would:
  `PAM_USER=$USER PAM_SERVICE=sudo /opt/fido2-ble-bridge/bin/python -I -m
  fido2_ble_bridge.local_session; echo $?`.

Wherever the key is asked, a `pam_exec` line first echoes a hint (in the terminal for `sudo`,
under the password field on the login and lock screens), because `pam_u2f` stays silent until
the key has answered. It is not `pam_echo`, which `sudo` silences (it always authenticates
with `PAM_SILENT`). It can never change the result.

To add a service, append its PAM service name to the first list, and rerun `sudo
pam-auth-update --enable fido2-ble-bridge`. Add it to the second list as well only if the check
must be skipped for it, which is safe only for services that only someone at the screen can
reach. In particular, to use the key for polkit (`pkexec`, the desktop's administrator
dialogs), add `polkit-1` to the first list only: the check then lets the key answer only polkit
prompts that come from your own session at this computer, so other users cannot get your key to
ask. The risk that remains is the one `sudo` has: programs running as you can trigger it. Never
add `su`, `su-l` or `polkit-1` to the second list: `su yourname` and `pkexec` let anyone on this
computer, or logged in over SSH, start a login as you, and your key would ask for your
fingerprint. If you touched it then, believing the prompt was your own, they would be logged
in as you, and your own login at that moment would fall back to the password because the key
is busy.

Reinstalling keeps your edited file: when the new version ships a different profile,
`install.sh` puts it in `/etc/fido2-ble-bridge/pam-profile.new` instead, shows the differences
and warns, so you can merge them. An unedited profile is replaced, and if it is enabled,
`install.sh` runs `pam-auth-update --enable fido2-ble-bridge` so that the new version takes
effect (it warns if `common-auth` was edited by hand and therefore not updated). If the key is
absent or fails, you get the password prompt. To undo: `sudo pam-auth-update --disable
fido2-ble-bridge`.

`pam-auth-update` exists on Debian and Ubuntu. Elsewhere, add these lines before the password
module in the PAM files of your display manager and screen locker (for example
`/etc/pam.d/gdm-password`):

```
auth [default=ignore] pam_exec.so quiet stdout /usr/bin/echo Bluetooth key: press its button, then touch the sensor when it lights up. No key? Wait for the password prompt.
auth sufficient pam_u2f.so authfile=/etc/fido2-ble-bridge/u2f_mappings origin=pam://fido2-ble-bridge cue userverification=1
```

For `sudo` (`/etc/pam.d/sudo`), add the same two lines with the local session check in front
of them, so that `sudo` in an SSH session skips the hint and the key:

```
auth [success=ignore default=2] pam_exec.so quiet /opt/fido2-ble-bridge/bin/python -I -m fido2_ble_bridge.local_session
auth [default=ignore] pam_exec.so quiet stdout /usr/bin/echo Bluetooth key: press its button, then touch the sensor when it lights up. No key? Wait for the password prompt.
auth sufficient pam_u2f.so authfile=/etc/fido2-ble-bridge/u2f_mappings origin=pam://fido2-ble-bridge cue userverification=1
```

Do not add the key to `su` or `polkit-1` without the check, for the reason above.

## Dual-boot with Windows

A key keeps one pairing per computer, and Windows and Linux on the same machine share its
Bluetooth adapter, so the key sees one computer. Pairing it in one system therefore replaces
the pairing the other one relies on, and the key stops working there. Setup warns about this
when it finds a Windows boot manager and asks before it pairs.

To use the key in both systems, pair it once, in Windows, and copy that pairing into BlueZ, so
Linux never pairs on its own. (The other direction, pairing in Linux and copying into Windows,
is harder: Windows only takes new keys for a device it has paired itself.)

1. **Pair the key in Windows** and check that it works there.
2. **Read the pairing from the Windows registry.** It is under
   `HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Keys\<adapter>\<device>`, and only
   the SYSTEM account may read it, for example with Sysinternals' `PsExec64.exe -s -i
   regedit.exe`. Export that key to a file. The names are addresses without colons, and
   `<device>` may be a temporary address: the key's real one is the `Address` value. From
   Linux, `chntpw` can read the same values from `Windows/System32/config/SYSTEM` (under the
   `ControlSet00N` that `Select\Current` names, usually `ControlSet001`, instead of
   `CurrentControlSet`) if the Windows partition is not encrypted with BitLocker and Windows
   was shut down with Restart, not Fast Startup.
3. **Convert the values** for BlueZ:

   | Windows value | BlueZ `info` file |
   | --- | --- |
   | `LTK` (16 bytes) | `Key=` of the long-term key, the same bytes as upper-case hex |
   | `KeyLength` | `EncSize=` (decimal) |
   | `ERand` (QWORD) | `Rand=` (decimal) |
   | `EDIV` (DWORD) | `EDiv=` (decimal) |
   | `IRK` (16 bytes) | `[IdentityResolvingKey] Key=`, with the byte order reversed (see below) |
   | `Address` (QWORD) | the key's directory name, `AA:BB:CC:DD:EE:FF` |
   | `AddressType` | `AddressType=static` for 1 (random), `public` for 0; a random identity address starts with C, D, E or F |
   | `AuthReq` | bit `0x08` set: an LE Secure Connections key |

   In a `.reg` export, binary values appear as `hex:` bytes, DWORD values as `dword:`
   hexadecimal numbers, and QWORD values as `hex(b):` bytes in little-endian order: reverse
   those before converting to decimal.
4. **Write the pairing into BlueZ.** Find the adapter's address with `bluetoothctl list`, then:

   ```console
   $ sudo systemctl stop bluetooth
   $ sudo install -d -m 0700 /var/lib/bluetooth/00:11:22:33:44:55/AA:BB:CC:DD:EE:FF
   $ sudoedit /var/lib/bluetooth/00:11:22:33:44:55/AA:BB:CC:DD:EE:FF/info
   $ sudo chmod 0600 /var/lib/bluetooth/00:11:22:33:44:55/AA:BB:CC:DD:EE:FF/info
   $ sudo systemctl start bluetooth
   $ bluetoothctl info AA:BB:CC:DD:EE:FF       # expect "Paired: yes" and "Bonded: yes"
   ```

   For an LE Secure Connections key (`AuthReq` has `0x08`, and `ERand` and `EDIV` are 0), the
   `info` file looks like this (`Authenticated=2`, or 3 if pairing used a passkey):

   ```
   [General]
   Name=My key
   AddressType=static
   SupportedTechnologies=LE;
   Trusted=true
   Blocked=false

   [IdentityResolvingKey]
   Key=00112233445566778899AABBCCDDEEFF

   [PeripheralLongTermKey]
   Key=00112233445566778899AABBCCDDEEFF
   Authenticated=2
   EncSize=16
   EDiv=0
   Rand=0

   [SlaveLongTermKey]
   Key=00112233445566778899AABBCCDDEEFF
   Authenticated=2
   EncSize=16
   EDiv=0
   Rand=0
   ```

   BlueZ writes the long-term key under both group names itself; older versions read only
   `[SlaveLongTermKey]`. For an older (legacy) pairing, use a single `[LongTermKey]` group with
   `Authenticated=0` (1 with a passkey) and the real `EncSize`, `EDiv` and `Rand`.
5. **Run setup with the address:** `sudo fido2-ble-bridge setup --address AA:BB:CC:DD:EE:FF`.
   It finds the bond and skips pairing. Do not let it pair again.
6. **Delete the exported file.** With the long-term key, someone nearby could decrypt or
   impersonate the link between the key and this computer; do not keep it, share it or
   commit it.

Things to know:

- **IRK byte order.** Tools disagree on whether the IRK must be reversed. If your key changes
  its address (resolvable private addresses) and BlueZ shows it as a new device instead of
  `AA:BB:CC:DD:EE:FF` after the import, try the bytes in Windows' order. A key with a fixed
  address does not need the IRK to reconnect.
- **Keep BlueZ's `Privacy` off** (the default in `/etc/bluetooth/main.conf`), so Linux uses the
  same adapter address the key bonded with under Windows.
- **Pairing again in either system breaks the other one again.** Repeat the import afterwards.
- Existing tools: [BlueVein](https://github.com/meowrch/BlueVein) keeps LE pairings in sync
  between both systems, and [bluetooth-dualboot](https://github.com/nbanks/bluetooth-dualboot)
  converts values by hand. [bt-dualboot](https://github.com/x2es/bt-dualboot) copies classic
  Bluetooth pairings from Linux to Windows.

## Using it

At a login prompt (the login or lock screen, `sudo` in your terminal), the profile first shows
"Bluetooth key: press its button, then touch the sensor when it lights up. No key? Wait for the
password prompt." Wake the key (before or after starting the login). The bridge waits up to
`connect_timeout` seconds for it, then `pam_u2f` shows "Please touch the device." and you touch
the sensor. The password prompt comes only when that fails: the key does not answer in time, or
it does not recognise your finger.

- **Faster with the key awake.** Press the key's button just before you start the login (as you
  press Enter on `sudo`, say): the bridge then connects as soon as it asks, instead of waiting
  for the key to wake. With a Feitian AllinPass K33 it took 3.7 to 4.2 s from the start of a
  login until "Please touch the device.", most of it the key waking and the connection being
  set up.
- **Wait time without the key.** When you log in without the key nearby, each prompt first waits
  `connect_timeout` seconds. Lower it in the config if that bothers you.
- **GNOME keyring.** The login keyring is encrypted with your password, so after a passwordless
  login GNOME asks for that password the first time something needs the keyring. This is a
  general consequence of passwordless login, not specific to this bridge.
- **Browsers.** Chrome and Firefox look for security keys on hidraw, so they should find the
  bridge for WebAuthn too. This is untested.

## Configuration

`/etc/fido2-ble-bridge/config.toml`; unknown keys are rejected. Setup writes `address`; restart
the service after editing (`sudo systemctl restart fido2-ble-bridge`).

| Key | Default | Meaning |
| --- | --- | --- |
| `address` | (required) | Bluetooth address of the bonded key |
| `adapter` | system default | Bluetooth adapter, e.g. `hci1`. Setup pairs on this adapter, and writes the one it paired on when the computer has several, so the bridge uses the adapter that holds the bond |
| `connect_timeout` | `10` | Seconds a request waits for the key to connect (1 to 120) |
| `request_timeout` | `60` | Further seconds one request may take, fingerprint wait included (5 to 300) |
| `idle_disconnect` | `10` | Seconds the link stays open after the last request (0 to 600) |
| `device_name` | `FIDO2 BLE bridge` | Name of the virtual HID device |

## Troubleshooting

- `journalctl -u fido2-ble-bridge -f` shows connections, timeouts and refusals.
- Setup finds **no key in pairing mode**: hold the button until the LED blinks fast, keep the
  key close, and make sure it is not connected to another device. A connected key does not
  advertise, so turn Bluetooth off on your phone or forget the key there.
- Setup says the key **refused the pairing**: put it back in pairing mode and run setup again;
  if it asked for a passkey, check the digits. If BlueZ still has an old pairing from before the
  key was reset, let setup remove it, or run `bluetoothctl remove AA:BB:CC:DD:EE:FF`.
- `check` (or setup's step 4) says **not bonded**: pair and trust the key again; `bluetoothctl
  info` must show `Bonded: yes`.
- `check` says **does not offer FIDO2 over BLE**: the key has no FIDO2 BLE service, or only
  legacy U2F over BLE, which this bridge does not support.
- `check` times out: wake the key and make sure it is not connected to another device (a
  phone, or another computer it is paired with) or to this computer through the desktop's
  Bluetooth settings. A connected key does not advertise, so the bridge cannot find it. Keys
  such as the K33 keep pairings with several computers but connect to one at a time: turn
  Bluetooth off on the other one. If the key was reset since it was paired here, its pairing
  here is stale: remove it and run setup again.
- `check` or setup says **initialization fragment while a frame was incomplete**: every
  notification from the key arrived twice, because two programs on this computer had it
  subscribed at the same moment (BlueZ sends a copy per subscriber), for example setup while
  the bridge still held its link from a login. Wait 10 seconds (`idle_disconnect`) and try
  again.
- `check` or a login says BlueZ **refuses to scan** (`org.bluez.Error.InProgress`), and
  `bluetoothctl scan le` fails the same way while `bluetoothctl show` reports `Discovering: no`:
  the Bluetooth controller is stuck, and the kernel log (`journalctl -k`) repeats
  `Opcode 0x2041 failed: -16` and `start background scanning failed: -16`. Logins cannot reach
  the key until the adapter is reset: `bluetoothctl power off`, then `bluetoothctl power on`.
- Logins sometimes fall back to the password, and the journal says **`authenticator
  disconnected`** in the middle of a request: the connection was lost. When `sudo btmon` shows
  `Disconnect Complete` with `Reason: Connection Timeout (0x08)` (the kernel log may add `ACL
  packet for unknown connection handle`), the key went quiet longer than the supervision
  timeout. Run setup again and accept its connection timing in step 3, or see
  [Manual setup](#2-configure-and-check). A key that drops a link it has just accepted, while
  BlueZ still reads its services, is connected again automatically within the connect timeout.
- Setup's **login test fails**: nothing was saved, so `/etc/fido2-ble-bridge/u2f_mappings` and
  PAM are as they were, and an earlier registration still works. Check the enrolled finger
  before trying again (`fido2-token -I /dev/hidrawN` must list `uv`).
- **`pam-auth-update` did not enable the profile**: it leaves `/etc/pam.d/common-auth` alone
  when that file was edited by hand ("Local modifications"). Merge the change yourself, or
  add the lines from [Manual setup](#5-test-then-enable-pam).
- Setup **does not enable a profile** whose `pam_u2f` line it finds weakened: restore
  `/usr/share/pam-configs/fido2-ble-bridge` from `packaging/pam-configs/`, and check
  `/etc/security/pam_u2f.conf` (read by `pam_u2f` 1.4 and newer) for `nouserok` or `alwaysok`.
- **`sudo` asks for the password although the key is near**: the local session check skipped
  the key, for example in an SSH session, or in a desktop terminal while you are also logged in
  over SSH. The command in [Manual setup](#5-test-then-enable-pam) prints its reason.
- Setup says the configured key **is not paired with this computer**: if you did not remove the
  pairing, see [Security model](#security-model) before you pair again.
- `fido2-ble-bridge -v check` adds debug logs from the bridge only; message contents are never
  logged.
- `pamu2fcfg` registers the wrong key: it uses the first FIDO device it finds, so unplug other
  security keys while registering (setup checks this for you).

## Status

Verified by the test suite: the CTAPHID and FIDO-BLE framing against the CTAP 2.1 spec
examples; the BLE link against a simulated authenticator (handshake, fragmentation with
sequence wraparound, keepalives, cancel, disconnects, timeouts, refusal of unbonded or
non-FIDO2 devices); every setup step against fakes of BlueZ's D-Bus API, the system's commands
and PAM; the shipped PAM profile through the real libpam (which services reach the key); and
end to end through the real kernel (`uhid`, hidraw), libfido2's `fido2-token`,
`pamu2fcfg` and `pam_u2f` with only the radio simulated. That includes a full fingerprint login,
its refusal on a failed fingerprint or a wrong signature, and setup's registration and login
test.

**Confirmed on hardware** with a Feitian AllinPass K33 (FIDO2 over Bluetooth LE and a
fingerprint sensor; CTAP 2.0 and 2.1-PRE) on Ubuntu 24.04 ARM64 with BlueZ 5.72: pairing,
setup's registration and its login test through `pam_u2f`. The K33 keeps bonds with two
computers, but only one can be connected at a time. It refuses messages split into fragments
shorter than its `fidoControlPointLength`, sends a single keepalive while it waits for the
finger, and sometimes asks for its PIN when registering (`pamu2fcfg` then prompts for it); the
bridge and setup handle all of these.

If you try another key, please open an issue with the key model and the output of
`fido2-ble-bridge check`, so this section can list keys that work.

## Development

From the `linux/` directory:

```console
$ uv sync
$ uv run pytest            # unit, link, bridge and setup tests
$ uv run ruff check . && uv run ruff format --check . && uv run mypy
```

The end-to-end tests in `tests/test_e2e_uhid.py` run when you can write `/dev/uhid` (root-only
by default; CI loosens it with a udev rule) and `fido2-token`, `pamu2fcfg` and `pam_u2f.so` are
installed. Point `FIDO2_TOKEN`, `PAMU2FCFG` and `PAM_U2F_SO` at other builds if needed; setup's
registration test is the exception and always uses the system's `pam_u2f.so`, as setup itself
does. They use `pam_start_confdir`, so they never touch `/etc/pam.d`. CI runs them on every
push.

Setup lives in `src/fido2_ble_bridge/setup_wizard.py`, with BlueZ pairing in `pairing.py` and the
PAM test in `pam.py`. Every system effect goes through small injectable pieces, so
`tests/test_setup_wizard.py` runs each step against the fakes in `tests/setup_fakes.py`.

### Possible speedups, not done

Measured on a K33 at a 20 ms connection interval, where each request to the key takes two to
four intervals:

- **`nodetect` on the `pam_u2f` line** skips pam_u2f's first request, which only checks that the
  key holds the credential: about 0.2 to 0.4 s per login. With a backup key also registered,
  pam_u2f would then no longer know which key to ask first.
- **A shorter handshake:** write the FIDO2 revision without reading the key's revision bitfield
  first, and reuse the control point length from the last connection: about 0.1 s.
- **System-wide BlueZ settings:** scanning at full duty while connecting, and turning off
  bluetoothd's battery and device-information plugins, which read the key on every connection:
  perhaps 0.2 to 0.5 s, but they apply to every Bluetooth device (GNOME would show no battery
  levels, for one).

## License

MIT; see [LICENSE](../LICENSE).
