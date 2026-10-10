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
| Nearby radio, no bond key | Jam the link, so login falls back to the password | Connect as your key: BlueZ requires encryption with the bond's LTK, and the bridge refuses unbonded addresses |
| Device spoofing your key's address | Fail the connection | Complete an encrypted connection, or produce a valid assertion |
| Compromised or buggy bridge | Make requests fail; read or alter relayed messages; capture a PIN typed into a CTAP client, because PIN key agreement is unauthenticated | Forge an assertion: it has no private key, and `pam_u2f` verifies every signature |
| Unprivileged local user, not on the seat | Nothing: udev grants the virtual hidraw node to the active seat user only | Talk to the key through the bridge |
| Logged-in seat user or root | Use the key through the bridge, as they could use a plugged-in USB key | Use it without your fingerprint, when the credential requires user verification |
| Someone with your key | Wake it | Pass the fingerprint check |

Prefer fingerprint verification (`pamu2fcfg -V`, `userverification=1`) over a PIN: with
built-in verification no secret ever crosses the bridge.

## Hardening in place

- Connections only to the configured address, and only when BlueZ reports it paired and bonded,
  checked before and after connecting.
- CTAP2 only; CTAPHID_MSG (U2F) is refused.
- Every length is bounded by the protocol maximum (7609 bytes on CTAPHID, the control point
  length on BLE); out-of-sequence or oversized frames drop the link.
- Message contents are never logged.
- systemd sandbox: `DynamicUser`, empty capability set, `PrivateNetwork`, `PrivateDevices` with
  only `/dev/uhid` bound in, `ProtectSystem=strict`, `MemoryDenyWriteExecute`,
  `SystemCallFilter=@system-service`.
- Runtime dependencies installed from binary wheels pinned by hash.
