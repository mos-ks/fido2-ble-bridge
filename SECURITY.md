# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's "Report a vulnerability" button on
the Security tab of this repository, not in a public issue.

## Threat model

fido2-ble-bridge relays CTAP2 messages between a local FIDO client (libfido2, `pam_u2f`, a
browser) and a Bluetooth LE authenticator. Authentication decisions are never made by the
bridge: the client generates the challenge and verifies the authenticator's signature against
a public key it registered earlier.

| Attacker | Can | Cannot |
| --- | --- | --- |
| Nearby radio, no bond key | Jam the link, so login falls back to the password | Connect as your key: for an LE bond BlueZ requires encryption with its LTK, and the bridge refuses unbonded addresses |
| Device spoofing your key's address | Fail the connection | Complete an encrypted connection (LE bond), or produce a valid assertion in any case |
| Remote attacker trying passwords over `sshd` | Nothing involving the key: the PAM profile only runs `pam_u2f` for local services | Make your key prompt for a fingerprint |
| Compromised or buggy bridge | Make requests fail; read or alter relayed messages; capture a PIN typed into a CTAP client, because PIN key agreement is unauthenticated | Forge an assertion: it has no private key, and `pam_u2f` verifies every signature |
| Any local user | Talk to the bonded key directly through BlueZ (its default D-Bus policy allows this; CTAP 2.1 section 11.4.13.1), so the key may prompt for a fingerprint | Get a signature without your fingerprint; open the bridge's hidraw node, which udev grants only to root and the active desktop user |
| Logged-in seat user or root | Use the key through the bridge, as they could use a plugged-in USB key | Use it without your fingerprint, when the credential requires user verification |
| Someone with your key | Wake it | Pass the fingerprint check |

Prefer fingerprint verification (`pamu2fcfg -V`, `userverification=1`) over a PIN: with
built-in verification no secret ever crosses the bridge.

## Hardening in place

- Connections only to the configured address, and only when BlueZ reports it paired and bonded,
  checked before and after connecting. Where BlueZ exposes `org.bluez.Bearer.LE1` (2025+), the
  LE bond itself is required. On older BlueZ a classic-only bond to a dual-mode device at that
  address would pass; FIDO keys bond over LE.
- The PAM profile is guarded with `pam_succeed_if service in …`, so remote services never
  reach the key.
- Every request has a hard deadline; GATT writes time out; an unacknowledged cancel retires the
  link so a late reply cannot answer the next request.
- CTAP2 only; CTAPHID_MSG (U2F) is refused.
- Every message is bounded by the CTAPHID maximum of 7609 bytes in both directions; outgoing BLE
  fragments by the control point length and the ATT MTU. Out-of-sequence or oversized frames,
  or a notification flood, drop the link.
- Message contents are never logged, and `bleak`/`dbus-fast` debug output (which would include
  raw GATT payloads) stays off even with `-v`.
- systemd sandbox: `DynamicUser`, empty capability set, `PrivateNetwork`, `PrivateDevices` (no
  device nodes at all; systemd passes the open `/dev/uhid` descriptor via `OpenFile=`),
  `ProtectSystem=strict`, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service`.
- Runtime dependencies installed from binary wheels pinned by hash.
