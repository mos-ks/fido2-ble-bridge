# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's "Report a vulnerability" button on
the Security tab of this repository, not in a public issue.

## Linux

This section covers the Linux bridge in [`linux/`](linux/README.md). Its README also has a
[security model](linux/README.md#security-model) written for users.

### Threat model

fido2-ble-bridge relays CTAP2 messages between a local FIDO client (libfido2, `pam_u2f`, a
browser) and a Bluetooth LE authenticator. Authentication decisions are never made by the
bridge: the client generates the challenge and verifies the authenticator's signature against
a public key it registered earlier.

| Attacker | Can | Cannot |
| --- | --- | --- |
| Nearby radio, no bond key | Jam the link, so login falls back to the password | Connect as your key: for an LE bond BlueZ requires encryption with its LTK, and the bridge refuses unbonded addresses |
| Device spoofing your key's address | Fail the connection | Complete an encrypted connection (LE bond), or produce a valid assertion in any case |
| Anyone logged in over SSH (you included), or trying passwords over `sshd` | Nothing involving the key through PAM: `sshd` is not in the PAM profile, and `sudo` in a remote or seatless session skips the key (the profile's local-session check) | Make your key prompt through a login, and so get your touch for their login |
| Another user of this computer, local or remote | Talk to the bonded key directly through BlueZ (its default D-Bus policy allows this; CTAP 2.1 section 11.4.13.1), so the key may prompt for a fingerprint; remove the key's pairing and pair a device of their own (same policy), which makes logins fail and makes setup warn on its next run | Start a login as you that uses your key: `su` and polkit (which let the caller name the account) are not in the profile, `sudo` only logs in the account that runs it, and the check refuses requests from another account's session; turn what the key signs for them into a login (`pam_u2f` checks its own challenge); get a device they paired registered without you seeing it and typing `yes` in setup; open the bridge's hidraw node, which udev grants only to root and the active desktop user |
| Compromised or buggy bridge | Make requests fail; read or alter relayed messages; capture a PIN typed into a CTAP client, because PIN key agreement is unauthenticated | Forge an assertion: it has no private key, and `pam_u2f` verifies every signature |
| Logged-in seat user, programs running as you, or root | Use the key through the bridge, as they could use a plugged-in USB key; someone who has your account (a stolen SSH key, say) can start `sudo` so that it looks local, for example through your systemd user instance, and make the key ask | Use it without your fingerprint, when the credential requires user verification |
| Someone with your key | Wake it | Pass the fingerprint check |

Who can make the key ask for a fingerprint through PAM, with the shipped profile: the login and
lock screens (only someone at the screen reaches them), and `sudo`, `sudo -i` and the console's
`login` when the local-session check (`fido2_ble_bridge.local_session`, run through `pam_exec`)
finds the request comes from a session of the account being logged in that sits at this
computer's seat and is not remote. For processes outside any login session, such as the
terminals GNOME and KDE start through systemd, it goes by the user's graphical session, as
polkit does, and additionally requires that none of the user's login sessions is remote or
seatless. The check fails closed: no answer, an error or a missing helper all mean no key.
Anything that runs as you can still trigger `sudo`, as with a USB key.

Setup does not verify the key's attestation, so it cannot prove a paired device is a genuine
key; it relies on you confirming the device it shows (a typed `yes`) and on the key itself
lighting up and reading your finger during registration and the login test.

Prefer fingerprint verification (`pamu2fcfg -V`, `userverification=1`) over a PIN: with
built-in verification no secret ever crosses the bridge.

### Hardening in place

- Connections only to the configured address, and only when BlueZ reports it paired and bonded,
  checked before and after connecting. Where BlueZ exposes `org.bluez.Bearer.LE1` (2025+), the
  LE bond itself is required. On older BlueZ a classic-only bond to a dual-mode device at that
  address would pass; FIDO keys bond over LE.
- The PAM profile uses the key only for the services it lists (`pam_succeed_if service in …`):
  login and lock screens, and `sudo`, `sudo -i` and `login` behind the local-session check
  (`pam_exec`), which skips the key for remote or seatless sessions, for another account's
  session, and whenever it cannot tell. `su`, `su-l`, `polkit-1` and `sshd` are not listed
  (the README shows how to add `polkit-1` behind the check, never without it). A hint before
  `pam_u2f` (`pam_exec` running `/usr/bin/echo`) is `[default=ignore]`, so it cannot change the
  result. `install.sh` re-applies an enabled profile when it changes, keeps one an admin edited,
  and warns when it cannot apply it.
- No request reaches the key twice: on a kept-open link only getInfo is ever sent again, and
  only when the key acknowledged none of it; any other request on a link idle for over a second
  goes only after a BLE PING with a random payload was echoed, and then exactly once.
- Every request has a hard deadline; GATT writes time out; an unacknowledged cancel retires the
  link so a late reply cannot answer the next request.
- CTAP2 only; CTAPHID_MSG (U2F) is refused.
- Every message is bounded by the CTAPHID maximum of 7609 bytes in both directions; outgoing BLE
  fragments are as long as the key's `fidoControlPointLength` (some keys refuse shorter ones;
  BlueZ turns a write longer than the ATT MTU into a long write). Out-of-sequence or oversized
  frames, or a notification flood, drop the link. A link the key dropped is still released, so
  BlueZ does not keep a stale notification subscription that would double every notification.
- Message contents are never logged, and `bleak`/`dbus-fast` debug output (which would include
  raw GATT payloads) stays off even with `-v`.
- systemd sandbox: a dedicated unprivileged system user, empty capability set, `PrivateNetwork`, `PrivateDevices` (a
  private `/dev` with pseudo-devices such as `/dev/null` but no physical devices; systemd passes
  the open `/dev/uhid` descriptor via `OpenFile=`), `ProtectSystem=strict`,
  `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service`.
- Runtime dependencies installed from binary wheels pinned by hash.
- `fido2-ble-bridge setup` pairs or uses only a device it showed you and you confirmed by
  typing `yes` (or named with `--address`), already bonded ones included, through its own BlueZ
  agent, which answers only for the key being paired and is never the default agent; it warns
  when the configured key lost its pairing; advertised device names are printed with control
  characters replaced. It finds the bridge's device by name, USB bus and the bridge's `phys`,
  refuses to choose between look-alikes, and sends nothing to it before libfido2 lists it. It
  enables PAM only after a login test through `pam_start_confdir` (outside `/etc/pam.d`) passed
  with the Bluetooth key alone, the installed profile's own `pam_u2f` line and exactly the
  authfile it then saves, and you typed `yes`; it refuses a profile whose `pam_u2f` line (or
  `/etc/security/pam_u2f.conf`) drops `userverification=1` or adds `alwaysok`, `nouserok`,
  `openasuser`, `expand` or unknown options. A new registration replaces all of the user's
  authfile lines, since `pam_u2f` reads only the last. Setup changes PAM only through
  `pam-auth-update` and never with `--force`, never retries a fingerprint request, and stops at
  Ctrl-C during the login test. To give the key faster and more tolerant connection timing
  (20 ms interval, 5 s supervision timeout) it edits BlueZ's settings file for the key (which holds the bond's long-term key) only after you agree: it
  touches only the `[ConnectionParameters]` group, reads the file the way GLib does so that a
  device alias another user set cannot fake a group or split a line, refuses an edit that would
  change any other line, writes atomically with mode 0600, and records the undo.
- Restricting BlueZ's D-Bus API to the `bluetooth` group, which closes direct access to the key
  and pairing changes by other users, is documented (README: Restricting BlueZ to the bluetooth
  group) but not done by setup, because it takes Bluetooth away from accounts outside the group.

## Windows

### Threat model

Fido2BleLogon is a credential provider (a logon tile) that runs inside LogonUI as SYSTEM. At
enrollment it creates a non-discoverable credential on the key with `credProtect` level 3 (usable
only after user verification) and the `hmac-secret` extension, and it seals the account password
with AES-256-GCM under a key derived (HKDF-SHA-256) from the key's hmac-secret output. The
ciphertext is bound to the relying party ID, account SID, user name and credential ID. At sign-in
the tile asks the key for one fingerprint-verified assertion with hmac-secret, verifies the
assertion signature against the enrolled public key, decrypts the password and hands Windows a
`KERB_INTERACTIVE_UNLOCK_LOGON` with the password protected by `CredProtect`.

| Attacker | Can | Cannot |
| --- | --- | --- |
| Someone with the PC but not the key | See the tile | Decrypt the password: the key alone produces the secret, and only after verifying the user |
| Someone with the key but not your finger or the key's PIN | Wake the key, make it ask for a finger | Get the secret: with `credProtect` level 3 the key refuses the credential without user verification |
| Someone with the key, its PIN and a copy of `enrollment.json` (an unencrypted disk) | Recover the Windows password | (use a strong key PIN and device encryption or BitLocker) |
| Nearby radio attacker or a device spoofing the key's address | Make the sign-in fail, so you use the password or PIN | Make the tile accept anything: the secret, the assertion signature and the GCM tag all have to match the enrolled credential |
| Nearby attacker during pairing | Advertise a fake key | Be paired silently: setup lists every key in pairing mode and asks you to choose |
| Program running as you, without admin rights | Nothing via the tile: Windows lets only elevated processes and SYSTEM open the key's FIDO service, the tile refuses credential dialogs, and its files are admin-only | Read the enrollment, change the tile, or get the password from it |
| Malware running as you, waiting for you to approve an elevated program | Influence which .NET runtime that elevated program loads (see below) | Affect the lock screen, which runs as SYSTEM |
| Administrator or SYSTEM on the running PC | Everything | |

Remaining risks:

- **The key's PIN** stands in for the fingerprint: FIDO2 treats both as user verification and the
  PC cannot tell which was used.
- **.NET runtime discovery in elevated programs.** Every credential provider is also loaded by
  elevated programs that open a Windows credential dialog. The tile then declines, but .NET is
  already loaded, and a framework-dependent COM component finds its runtime through `DOTNET_ROOT`
  if that variable is set in the user's environment. .NET does not support self-contained COM
  components (NETSDK1128); a native build of the tile would remove this. Keep no `DOTNET_*`
  variables in your user environment; the installer warns if it finds any.
- **Fingerprint attempts.** Keys like the Feitian AllinPass K33 lock after 15 failed matches and
  need a reset. A request that ends without a match (timed out, cancelled) may count too.

### Hardening in place

- The tile is offered only for logon and unlock (`CPUS_LOGON`, `CPUS_UNLOCK_WORKSTATION`); every
  other scenario, including Credential UI, gets `E_NOTIMPL`, and the installer checks this.
- The install folder (`C:\Program Files\Fido2BleLogon`) and the data folder
  (`C:\ProgramData\Fido2BleLogon`) are owned by Administrators and writable only by SYSTEM and
  Administrators; the tile refuses data that someone else owns or that is reached through a link.
- The installer builds from a copy of the sources in an admin-only folder with a clean
  environment (no per-user NuGet, MSBuild or `DOTNET_*` settings) and verifies the result.
- P/Invokes resolve from System32 only; startup hooks are disabled in the tile's runtime
  configuration.
- The tile never retries a rejected fingerprint. Automatic attempts happen only while waiting for
  the key to wake (no fingerprint request) or, after a request timed out, only once the key went
  to sleep and was woken again. With keys that report it (`getUVRetries`), it asks for
  confirmation before the last three attempts.
- Each Bluetooth request has a hard time limit, CBOR nesting and message sizes are bounded, and the
  frame queue is bounded, so a misbehaving key cannot hang or exhaust the lock screen.
- The decrypted password lives only in a buffer that is cleared right after the logon is handed to
  Windows or when the attempt is abandoned. Logs never contain the password or the serialization.
- Safe Mode never loads the tile, and the file `C:\ProgramData\Fido2BleLogon\disabled` turns it off.
