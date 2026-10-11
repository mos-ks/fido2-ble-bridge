# Fido2BleLogon: Windows sign-in with a Bluetooth FIDO2 key

Sign in to a **local Windows account** with a **Bluetooth LE FIDO2 security key** and its
fingerprint sensor: lock the PC, press the key's button, touch the sensor. No cable, no
Windows Hello hardware, no Microsoft or Entra account.

Windows' own security-key sign-in only works for Entra ID (work) accounts. Fido2BleLogon adds a
sign-in option (a credential provider) to the logon and lock screen for local accounts. Your
password and PIN keep working as before.

```
lock screen ──► Fido2BleLogon tile ──BLE, CTAP2──► key: checks your fingerprint,
    ▲          (runs as SYSTEM)                    returns its hmac-secret output
    │                                                         │
    └── signs in with your password ◄── decrypts it ◄─────────┘
                                        (enrollment.json, AES-256-GCM)
```

## Requirements

- Windows 10 version 2004 or later, or Windows 11, 64-bit
- A local account with a password, and administrator rights for setup
- A FIDO2 key that works over Bluetooth LE and has a built-in fingerprint sensor, with the
  `hmac-secret` and `credProtect` extensions. `fido2-ble-logon probe` checks this.
- The .NET 10 SDK; setup offers to install it with winget

Tested with a **Feitian AllinPass K33** on Windows 11. Other keys that meet the requirements
should work; please report models you try. The same K33 also works with the
[Linux bridge](../linux/README.md) on another computer: it keeps a pairing with each, but
connects to one at a time. For Windows and Linux on the same PC (dual boot), see
[Dual-boot with Windows](../linux/README.md#dual-boot-with-windows).

## Setup

```console
> git clone https://github.com/mos-ks/fido2-ble-bridge
> cd fido2-ble-bridge\windows
> setup.cmd
```

`setup.cmd` asks for administrator rights once, then:

1. installs the .NET 10 SDK if it is missing (asks first),
2. builds the tile and the `fido2-ble-logon` command in an admin-only folder and installs them to
   `C:\Program Files\Fido2BleLogon`,
3. pairs the key if none is paired: when asked, hold the key's button about 5 seconds until its
   LED blinks fast (see your key's manual),
4. enrolls your account: type your Windows password, then touch the sensor twice,
5. makes the fingerprint tile the preselected sign-in option.

Run it from the account you want to sign in to. Running it again updates the installation and
asks before replacing your enrollment.

## Using it

Lock the PC (Windows+L) or sign out. The fingerprint tile is preselected:

- If the key is asleep, the tile shows **Press the button on your security key**. Press it, then
  touch the sensor when the tile says so. You are signed in.
- If nobody touches the sensor in time, the tile waits until the key has gone to sleep and you
  wake it again, or until you click **Try again**. It never asks for your finger again by itself
  while the key is still awake.
- If the key rejects the finger, the tile says so (with the attempts left, if the key reports
  them) and waits for **Try again**.

Password and PIN stay under **Sign-in options**. After you change your Windows password, run
`setup.cmd` again (or `fido2-ble-logon enroll`).

## Security model

Enrollment creates a credential on the key with `credProtect` level 3 (the key uses it only
after verifying the user) and the `hmac-secret` extension. The key's hmac-secret output for that
credential, which it releases only after a fingerprint match, is the input to an AES-256-GCM key
that encrypts your Windows password. The ciphertext is bound to the account SID, user name,
credential ID and relying party ID, and is stored in `C:\ProgramData\Fido2BleLogon\enrollment.json`.
Unlocking needs the physical key and a fingerprint match. The salt and the key agreement travel
encrypted over Bluetooth (CTAP2 PIN/UV protocol), and the tile checks the key's signature.

On top of that:

- **Logon and lock screen only.** The tile refuses every other use, including the credential
  dialogs that programs can open (`CredUIPromptForWindowsCredentials`), so no program can ask it
  for your password.
- **Wiped from memory.** The tile holds the decrypted password only in a buffer it clears right
  after handing the logon to Windows, or as soon as the sign-in is abandoned.
- **Admin-only files.** The program folder and the data folder are owned by Administrators and
  writable only by SYSTEM and Administrators; the tile refuses data that someone else owns or
  that is reached through a link.
- **Built in a clean, admin-only folder.** The installer builds from source with a clean
  environment, so per-user settings can't feed into code that runs as SYSTEM.
- **No secrets in logs.** The log never contains the password, the serialization or its size.
- **Robust inside LogonUI.** Every call is guarded, so an error shows a message on the tile
  instead of taking down the lock screen.
- **Lockout safety.** Keys like the K33 lock after 15 failed fingerprint matches and need a reset.
  The tile never retries a rejected finger and asks again on its own only after the key went to
  sleep and was woken. If the key reports how many attempts are left (CTAP 2.1 `getUVRetries`),
  the tile shows the count and asks you to confirm before using the last three.

What it does **not** protect against:

- **The key's PIN.** FIDO2 treats a PIN like a fingerprint, and the PC cannot tell which one the
  key used. Someone with the key, its PIN and a copy of `enrollment.json` can recover the
  password. Use a strong key PIN.
- **An unencrypted disk.** `enrollment.json` is protected by ACLs only while Windows runs. Turn on
  device encryption or BitLocker.
- **Administrators on the running PC**, who can do anything the tile can.
- **Malware already running as you, trying to become administrator.** Like every credential
  provider, the tile is also loaded by elevated programs that open a credential dialog (it then
  declines), and .NET in such a program picks its runtime partly from your user environment
  (`DOTNET_ROOT`). Malware running as you could plant a runtime there and wait for you to approve
  such a program. The lock screen is not affected (it runs as SYSTEM). .NET can't bundle the
  runtime into a COM component; a native build would close this.
- **Someone with your key and your finger.**
- **Your password.** It still works, so keep it strong.

See [../SECURITY.md](../SECURITY.md#windows) for the threat model.

## If something goes wrong

- Password and PIN keep working: choose them under **Sign-in options**.
- **Turn the tile off** (elevated): `New-Item -ItemType File C:\ProgramData\Fido2BleLogon\disabled`
- **Safe Mode** never loads the tile.
- **Uninstall** (elevated): `powershell -NoProfile -ExecutionPolicy Bypass -File scripts\uninstall.ps1`
  (add `-RemoveData` to delete the enrollment too).
- The tile's log: `C:\ProgramData\Fido2BleLogon\logs\provider.log` (readable by administrators).
- **Couldn't reach your security key:** the key may be connected to another device (a phone, or
  another computer it is paired with, such as one running the Linux bridge); a connected key
  doesn't advertise. Turn Bluetooth off there.

## Command reference

`fido2-ble-logon` is installed to `C:\Program Files\Fido2BleLogon\cli`. Run it from an elevated
terminal (except `keys`).

| Command | What it does |
| --- | --- |
| `probe` | Connects to the key and shows what it supports |
| `pair` | Pairs a key that is in pairing mode (skipped if one is paired) |
| `keys` | Lists paired Bluetooth security keys |
| `enroll` | Links your Windows password to the key (password, then two touches) |
| `test` | Unlocks the stored password with one touch and checks it with Windows |
| `status` | Shows the enrollment |
| `default on` / `default off` | Preselects the fingerprint tile, or lets Windows choose again |
| `unenroll` | Deletes the enrollment |

## Development

```console
> dotnet build Fido2BleLogon.slnx
> dotnet test tests\Fido2BleLogon.Core.Tests
> src\Fido2BleLogon.CpHarness\bin\x64\Debug\net10.0-windows10.0.19041.0\fido2-ble-logon-cphost.exe selftest
```

- `src/Fido2BleLogon.Core`: CTAP2 over BLE, the CTAP2 client, the enrollment and the vault.
- `src/Fido2BleLogon.CredentialProvider`: the tile, a .NET COM server loaded by LogonUI.
- `src/Fido2BleLogon.Cli`: the `fido2-ble-logon` command.
- `src/Fido2BleLogon.CpHarness`: drives the tile like LogonUI does. `selftest` runs offline with a
  scripted key; `simulate` (elevated, with the real key) runs a full sign-in without the lock
  screen.
- `tests/Fido2BleLogon.Core.Tests`: unit tests against a simulated authenticator that also checks
  that every request is canonical CBOR.

## License

MIT; see [../LICENSE](../LICENSE).
