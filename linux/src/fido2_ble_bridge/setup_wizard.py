"""`fido2-ble-bridge setup`: prerequisites, pairing, config, service, fingerprint, registration,
a PAM test and enabling PAM, one step at a time.

Every step looks first and skips what is already done, so running setup again is safe and only
repeats what is missing. Each change it makes is recorded with how to undo it, and the summary
at the end lists them. All system access goes through small injectable pieces (Paths, Runner,
Console, the D-Bus connection, PAM and the key check), so tests run each step against fakes.

Fingerprint safety: registering and the PAM test each ask the key for user verification once.
Nothing is retried automatically, because some keys lock or reset after repeated failed
matches; on failure setup stops and says how to continue.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import pwd
import re
import shutil
import subprocess
import tempfile
import time
import tomllib
from collections.abc import Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, TypeVar

from . import pam
from .ble_link import KeyNotReachable, KeyNotTrusted, KeyUnsupported
from .config import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_MAPPINGS_PATH,
    PLACEHOLDER_ADDRESS,
    Config,
    ConfigError,
    load_config,
    parse_config,
)
from .console import Console, TerminalConsole, choose, confirm, device_name
from .daemon import CheckResult, check_key
from .pairing import (
    ALREADY_EXISTS,
    BLOCKED,
    BluetoothError,
    BluezPairing,
    BtDevice,
    Bus,
    PairingAgent,
    connect_system_bus,
    pairing_advice,
)
from .uhid import BRIDGE_PHYS

UNIT = "fido2-ble-bridge"
PAM_PROFILE = "fido2-ble-bridge"
PAM_TEST_SERVICE = "fido2-ble-bridge-setup-test"
MIN_BLUEZ = (5, 65)  # Device1.Bonded, which the bridge's bond check needs
MIN_SYSTEMD = 253  # OpenFile=, which hands the sandboxed service /dev/uhid
STEPS = 8
BLUEZ_STORAGE = "/var/lib/bluetooth"
# The key's LE connection parameters, as BlueZ keeps them in its settings file for the key and
# loads them into the kernel when bluetoothd starts (intervals in 1.25 ms, timeout in 10 ms).
# The kernel's own defaults, except for the supervision timeout: 5 s instead of 0.42 s, which a
# key that pauses its radio a little longer, busy or a few metres away, misses mid-login.
SUPERVISION_TIMEOUT = 500
LINK_PARAMETERS = (
    ("MinInterval", 24),
    ("MaxInterval", 40),
    ("Latency", 0),
    ("Timeout", SUPERVISION_TIMEOUT),
)

# Package names per distribution family: the install command, then requirement -> package.
PACKAGES: dict[str, tuple[str, dict[str, str]]] = {
    "debian": (
        "apt-get install",
        {
            "bluez": "bluez",
            "pam_u2f": "libpam-u2f",
            "pamu2fcfg": "pamu2fcfg",
            "fido2-token": "fido2-tools",
        },
    ),
    "fedora": (
        "dnf install",
        {
            "bluez": "bluez",
            "pam_u2f": "pam-u2f",
            "pamu2fcfg": "pamu2fcfg",
            "fido2-token": "fido2-tools",
        },
    ),
    "arch": (
        "pacman -S",
        {"bluez": "bluez", "pam_u2f": "pam-u2f", "pamu2fcfg": "pam-u2f", "fido2-token": "libfido2"},
    ),
    "suse": (
        "zypper install",
        {
            "bluez": "bluez",
            "pam_u2f": "pam_u2f",
            "pamu2fcfg": "pam_u2f",
            "fido2-token": "libfido2-utils",
        },
    ),
}

_NEW_CONFIG = """\
# fido2-ble-bridge configuration. config.toml.example in the project lists every setting.

# Bluetooth address of your bonded key (written by `fido2-ble-bridge setup`).
address = "{address}"
"""
_T = TypeVar("_T")
_ADDRESS_LINE = re.compile(r"^[ \t]*address[ \t]*=.*$", re.MULTILINE)
_ADAPTER_LINE = re.compile(r"^[ \t]*adapter[ \t]*=.*$", re.MULTILINE)
_BT_ADDRESS = re.compile(r"[0-9A-F]{2}(:[0-9A-F]{2}){5}")
_KEY_FILE_GROUP = re.compile(r"\s*\[(?P<name>[^\]]*)\]\s*")
_KEY_FILE_ENTRY = re.compile(r"\s*(?P<key>[A-Za-z0-9-]+)\s*=\s*(?P<value>.*?)\s*")


class SetupError(Exception):
    """Stop setup; the message says what went wrong and what to do next."""


@dataclass(frozen=True)
class Change:
    what: str
    undo: str


@dataclass(frozen=True)
class SetupOptions:
    user: str | None = None
    address: str | None = None
    yes: bool = False
    """Install missing packages without asking."""
    no_pam: bool = False


@dataclass(frozen=True)
class Timing:
    scan: float = 30.0
    """Seconds to look for a key in pairing mode."""
    settle: float = 3.0
    """Seconds to keep looking after the first key shows up, to catch others."""
    poll: float = 0.5
    pair: float = 60.0
    wake: float = 30.0
    """Seconds the key check waits for the key to be woken."""
    bluetooth: float = 20.0
    """Seconds to wait for BlueZ to list the key again after restarting it."""
    node: float = 15.0
    """Seconds to wait for the virtual hidraw device after starting the service."""


@dataclass(frozen=True)
class Paths:
    """Where setup looks and writes; tests point `root` at a temporary directory."""

    root: Path = Path("/")

    def at(self, path: str | Path) -> Path:
        return self.root / str(path).lstrip("/")

    @property
    def config(self) -> Path:
        return self.at(DEFAULT_CONFIG_PATH)

    @property
    def mappings(self) -> Path:
        return self.at(DEFAULT_MAPPINGS_PATH)

    @property
    def unit(self) -> Path:
        return self.at(f"/etc/systemd/system/{UNIT}.service")

    @property
    def pam_profile(self) -> Path:
        return self.at(f"/usr/share/pam-configs/{PAM_PROFILE}")

    @property
    def common_auth(self) -> Path:
        return self.at("/etc/pam.d/common-auth")

    @property
    def pam_u2f_conf(self) -> Path:
        """pam_u2f's own defaults (pam_u2f 1.4 and newer read it)."""
        return self.at("/etc/security/pam_u2f.conf")

    @property
    def uhid(self) -> Path:
        return self.at("/dev/uhid")

    @property
    def hidraw_class(self) -> Path:
        return self.at("/sys/class/hidraw")

    @property
    def bluetooth_class(self) -> Path:
        return self.at("/sys/class/bluetooth")

    @property
    def os_release(self) -> list[Path]:
        return [self.at("/etc/os-release"), self.at("/usr/lib/os-release")]

    @property
    def bluetoothd(self) -> list[Path]:
        return [
            self.at("/usr/libexec/bluetooth/bluetoothd"),
            self.at("/usr/lib/bluetooth/bluetoothd"),
            self.at("/usr/sbin/bluetoothd"),
        ]

    @property
    def windows_boot(self) -> list[Path]:
        """Where a Windows boot manager on the EFI system partition shows up."""
        return [self.at(f"{esp}/EFI/Microsoft") for esp in ("/boot/efi", "/boot", "/efi")]


@dataclass(frozen=True)
class Completed:
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class Runner(Protocol):
    def which(self, name: str) -> str | None: ...

    def run(
        self,
        argv: Sequence[str],
        *,
        interactive: bool = False,
        capture: bool = True,
        env: Mapping[str, str] | None = None,
        timeout: float | None = 60.0,
    ) -> Completed:
        """Run a command. `interactive` shares the terminal's stdin and stderr with it (PIN
        prompts, touch cues); `capture` collects its stdout."""


class SystemRunner:
    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def run(
        self,
        argv: Sequence[str],
        *,
        interactive: bool = False,
        capture: bool = True,
        env: Mapping[str, str] | None = None,
        timeout: float | None = 60.0,
    ) -> Completed:
        try:
            done = subprocess.run(  # noqa: S603 -- fixed argument lists built by setup, no shell
                list(argv),
                stdin=None if interactive else subprocess.DEVNULL,
                stdout=subprocess.PIPE if capture else None,
                stderr=None if interactive else subprocess.PIPE,
                text=True,
                env={**os.environ, **env} if env else None,
                timeout=None if interactive else timeout,
                check=False,
            )
        except FileNotFoundError:
            return Completed(127, "", f"{argv[0]}: not found")
        except OSError as exc:  # there but not executable, for example
            return Completed(126, "", f"{argv[0]}: {exc.strerror or exc}")
        except subprocess.TimeoutExpired:
            return Completed(124, "", f"{argv[0]}: no answer within {timeout:g}s")
        return Completed(done.returncode, done.stdout or "", done.stderr or "")


class PamBackend(Protocol):
    def available(self) -> bool: ...

    def authenticate(
        self, confdir: Path, service: str, user: str, on_message: Callable[[str], None]
    ) -> pam.PamResult: ...


class SystemPam:
    def available(self) -> bool:
        return pam.available()

    def authenticate(
        self, confdir: Path, service: str, user: str, on_message: Callable[[str], None]
    ) -> pam.PamResult:
        return pam.authenticate(confdir, service, user, on_message)


async def _check_key(config: Config, connect_timeout: float) -> CheckResult:
    return await check_key(config, connect_timeout=connect_timeout)


def _euid() -> int:
    return os.geteuid()


def _user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
    except KeyError:
        return False
    return True


@dataclass
class Host:
    """Everything setup touches outside its own process."""

    console: Console
    runner: Runner = field(default_factory=SystemRunner)
    paths: Paths = field(default_factory=Paths)
    bus: Callable[[], Coroutine[Any, Any, Bus]] = connect_system_bus
    pam: PamBackend = field(default_factory=SystemPam)
    check: Callable[[Config, float], Coroutine[Any, Any, CheckResult]] = _check_key
    euid: int = field(default_factory=_euid)
    sudo_user: str | None = field(default_factory=lambda: os.environ.get("SUDO_USER"))
    user_exists: Callable[[str], bool] = _user_exists
    timing: Timing = field(default_factory=Timing)


def resolve_user(explicit: str | None, sudo_user: str | None, exists: Callable[[str], bool]) -> str:
    """--user, else the account that ran sudo; root only when asked for by name."""
    if explicit is not None:
        name = explicit
    elif sudo_user and sudo_user != "root":
        name = sudo_user
    else:
        raise SetupError(
            "cannot tell which account to set up. Run setup with sudo from that account, or "
            "name it with --user NAME (--user root to set up root itself)."
        )
    if not exists(name):
        raise SetupError(f"there is no user account named {name!r}.")
    return name


def distro_family(os_release: str) -> str | None:
    """debian, fedora, arch or suse, from the text of /etc/os-release."""
    fields: dict[str, str] = {}
    for line in os_release.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields[key.strip()] = value.strip().strip("\"'")
    ids = {fields.get("ID", ""), *fields.get("ID_LIKE", "").split()}
    if ids & {"debian", "ubuntu"}:
        return "debian"
    if ids & {"fedora", "rhel", "centos"}:
        return "fedora"
    if "arch" in ids:
        return "arch"
    if any("suse" in name for name in ids):
        return "suse"
    return None


def parse_version(text: str) -> tuple[int, ...] | None:
    """The first dotted number: `systemd 255 (255.4-1)` -> (255,), `5.72` -> (5, 72)."""
    match = re.search(r"\d+(?:\.\d+)*", text)
    return tuple(int(part) for part in match.group().split(".")) if match else None


def set_address(text: str, address: str) -> str:
    """The config text with its `address =` line replaced (or added), all else unchanged."""
    line = f'address = "{address}"'
    if _ADDRESS_LINE.search(text):
        return _ADDRESS_LINE.sub(lambda _match: line, text, count=1)
    return f"{line}\n{text}"


def set_adapter(text: str, adapter: str) -> str:
    """The config text with its `adapter =` line replaced, or added after the address line."""
    line = f'adapter = "{adapter}"'
    if _ADAPTER_LINE.search(text):
        return _ADAPTER_LINE.sub(lambda _match: line, text, count=1)
    if address := _ADDRESS_LINE.search(text):
        return f"{text[: address.end()]}\n{line}{text[address.end() :]}"
    return f"{line}\n{text}"


def has_bluetooth_adapter(bluetooth_class: Path) -> bool:
    """Whether the kernel has a Bluetooth adapter (hciN; hciN:M entries are connections)."""
    try:
        return any(re.fullmatch(r"hci\d+", entry.name) for entry in bluetooth_class.iterdir())
    except OSError:
        return False


class AmbiguousDevice(Exception):
    """More than one device looks like the bridge's."""


def find_hidraw_nodes(hidraw_class: Path, name: str) -> list[str]:
    """/dev/hidrawN of every device that looks like the bridge's, in numeric order: a uhid
    device (a real USB device never lives under /sys/devices/virtual/misc/uhid) on the USB bus
    with the bridge's phys and the configured name. BlueZ's uhid devices for Bluetooth keyboards
    and the like are on the Bluetooth bus, whatever name the remote device gives itself."""
    found: list[tuple[int, str]] = []
    for entry in hidraw_class.glob("hidraw*"):
        number = entry.name.removeprefix("hidraw")
        if not number.isdigit():
            continue
        device = entry / "device"
        try:
            uevent = (device / "uevent").read_text()
        except OSError:
            continue
        fields: dict[str, str] = {}
        for line in uevent.splitlines():
            key, _, value = line.partition("=")
            fields[key] = value
        if (
            fields.get("HID_NAME") == name
            and fields.get("HID_PHYS") == BRIDGE_PHYS
            and fields.get("HID_ID", "").split(":", 1)[0].upper() == "0003"
            and "/devices/virtual/misc/uhid/" in os.path.realpath(device) + "/"
        ):
            found.append((int(number), f"/dev/{entry.name}"))
    return [node for _number, node in sorted(found)]


def find_hidraw_node(hidraw_class: Path, name: str) -> str | None:
    """The bridge's /dev/hidrawN (see find_hidraw_nodes); None if there is none, and
    AmbiguousDevice if several devices look like it, rather than guessing."""
    nodes = find_hidraw_nodes(hidraw_class, name)
    if len(nodes) > 1:
        raise AmbiguousDevice(f"{', '.join(nodes)} all look like the bridge's device ({name})")
    return nodes[0] if nodes else None


def parse_options(token_info: str) -> set[str] | None:
    """The options `fido2-token -I` prints (`uv`, `clientPin`, `nouv`, ...), or None if the
    device answered without CTAP2 getInfo (libfido2 fell back to U2F, e.g. a sleeping key)."""
    for line in token_info.splitlines():
        if line.startswith("options:"):
            return {option.strip() for option in line[len("options:") :].split(",")}
    return None


def _fields(line: str) -> list[str]:
    """An authfile line's fields as pam_u2f reads them (strtok on ':', so empty ones vanish):
    the user, then one field per credential."""
    return [field for field in line.split(":") if field]


def mapping_lines(text: str, user: str) -> list[str]:
    """Every authfile line for `user`, in order."""
    return [line for line in text.splitlines() if _fields(line)[:1] == [user]]


def mapping_line(text: str, user: str) -> str | None:
    """`user`'s authfile line that counts: pam_u2f reads them all and keeps only the last."""
    lines = mapping_lines(text, user)
    return lines[-1] if lines else None


def credential_count(line: str) -> int:
    return len(_fields(line)) - 1


def merge_mapping(text: str, user: str, entry: str, *, append: bool = False) -> str:
    """The authfile with all of `user`'s lines replaced by the single line `entry`
    (`user:...`), or with `entry` (`:...`, pamu2fcfg -n) appended to `user`'s last line, the
    one pam_u2f uses. Other users' lines stay as they are."""
    lines = text.splitlines()
    mine = [index for index, line in enumerate(lines) if _fields(line)[:1] == [user]]
    if not mine:
        lines.append(user + entry if append else entry)
    elif append:
        lines[mine[-1]] += entry
    else:
        lines[mine[0]] = entry
        lines = [line for index, line in enumerate(lines) if index not in mine[1:]]
    return "\n".join(lines) + "\n"


def _valid_mapping(entry: str, prefix: str) -> bool:
    """pamu2fcfg output: `prefix` then credentials `keyhandle,publickey,type,options`."""
    if not entry.startswith(prefix) or any(char.isspace() for char in entry):
        return False
    credentials = entry[len(prefix) :].split(":")
    return all(len(credential.split(",")) >= 4 for credential in credentials)


def write_file(path: Path, text: str, mode: int = 0o644) -> None:
    """Replace `path` atomically: readers see the old file or the new one, never half of it."""
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        if os.geteuid() == 0:
            os.chown(temporary, 0, 0)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def valid_link_parameters(min_interval: int, max_interval: int, latency: int, timeout: int) -> bool:
    """The kernel's checks (hci_check_conn_params): BlueZ loads whatever its settings file
    says, and the kernel ignores parameters that fail them."""
    if not 6 <= min_interval <= max_interval <= 3200 or not 10 <= timeout <= 3200:
        return False
    if max_interval >= timeout * 8:
        return False
    return 0 <= latency <= 499 and latency <= timeout * 4 // max_interval - 1


def _key_file_lines(text: str) -> tuple[list[str], int | None, int]:
    """`text`'s lines, and where its [ConnectionParameters] group starts (the header's index,
    None if absent) and ends (the next header's index, or the line count)."""
    lines = text.splitlines(keepends=True)
    headers = [
        (index, match["name"])
        for index, line in enumerate(lines)
        if (match := _KEY_FILE_GROUP.fullmatch(line.rstrip("\r\n")))
    ]
    start = next((index for index, name in headers if name == "ConnectionParameters"), None)
    end = next((index for index, _name in headers if start is not None and index > start), None)
    return lines, start, len(lines) if end is None else end


def link_parameters(text: str) -> dict[str, str] | None:
    """The [ConnectionParameters] entries of a BlueZ device settings file (a GLib key file),
    None if it has no such group."""
    lines, start, end = _key_file_lines(text)
    if start is None:
        return None
    return {
        match["key"]: match["value"]
        for line in lines[start + 1 : end]
        if (match := _KEY_FILE_ENTRY.fullmatch(line.rstrip("\r\n")))
    }


def _allows_timeout(entries: dict[str, str]) -> bool:
    try:
        values = [int(entries[key]) for key, _value in LINK_PARAMETERS]
    except (KeyError, ValueError):
        return False
    return valid_link_parameters(*values) and values[3] >= SUPERVISION_TIMEOUT


def with_link_parameters(text: str) -> str | None:
    """`text`, a BlueZ device settings file, with connection parameters that give the key
    SUPERVISION_TIMEOUT; None if the ones it has already do. Only that group changes: the rest,
    bond keys included, stays as it is, byte for byte."""
    lines, start, end = _key_file_lines(text)
    ours = [f"{key}={value}\n" for key, value in LINK_PARAMETERS]
    if start is None:
        group = "[ConnectionParameters]\n" + "".join(ours)
        if not text:
            return group
        # A blank line between groups, as BlueZ writes them.
        return text + ("\n" if text.endswith("\n") else "\n\n") + group
    entries = link_parameters(text)
    if entries is not None and _allows_timeout(entries):
        return None
    names = {key for key, _value in LINK_PARAMETERS}
    kept = [
        line
        for line in lines[start + 1 : end]
        if not ((match := _KEY_FILE_ENTRY.fullmatch(line.rstrip("\r\n"))) and match["key"] in names)
    ]
    header = lines[start] if lines[start].endswith("\n") else lines[start] + "\n"
    return "".join([*lines[:start], header, *ours, *kept, *lines[end:]])


def _first_line(text: str) -> str:
    return next((line.strip() for line in text.splitlines() if line.strip()), "")


def _describe(device: BtDevice) -> str:
    # The name is whatever the device advertises: made printable, and quoted so that it cannot
    # pass for setup's own text.
    if device.name is None:
        return f"{device.address}  (no name)"
    return f'{device.address}  "{device_name(device.name)}"'


class Setup:
    def __init__(self, options: SetupOptions, host: Host) -> None:
        self.options = options
        self.host = host
        self.console = host.console
        self.runner = host.runner
        self.paths = host.paths
        self.timing = host.timing
        self.changes: list[Change] = []
        self.user = ""
        self.tools: dict[str, str] = {}
        self.adapter: str | None = None
        """The adapter step 2 used, when the config must name it (BlueZ has several)."""
        self.registered = False
        """The Bluetooth key was registered in this run (it is saved once the test passed)."""
        self.new_entry: str | None = None
        """The user's new authfile line, from pamu2fcfg; not saved yet."""
        self.backup_entries: list[str] = []
        """Backup-key credentials (`:...`) for the user's line; not saved yet."""
        self.tested_profile: str | None = None
        """The PAM profile's text as step 7 tested its pam_u2f line; step 8 enables only that."""
        self.key_adapter: str | None = None
        """The adapter (hciN) that holds the key's bond, from step 2."""
        self.bond_file: Path | None = None
        """BlueZ's settings file for the key, from step 2; None if BlueZ did not say where."""
        self._loop: asyncio.Runner | None = None

    def say(self, text: str = "") -> None:
        self.console.say(text)

    def run(self) -> int:
        try:
            self._run_steps()
        except SetupError as exc:
            self.say(f"\nStopped: {exc}")
            self._summary()
            return 1
        except KeyboardInterrupt:
            self.say("\nInterrupted.")
            self._summary()
            return 130
        self._summary()
        if self._pam_enabled():
            self.say("\nSetup is complete. Local logins, sudo and the lock screen accept the key.")
        else:
            self.say("\nSetup is complete, but PAM does not use the key yet (see step 8).")
        return 0

    def _run_steps(self) -> None:
        if self.host.euid != 0:
            raise SetupError(
                "setup changes system settings, so it must run as root: sudo fido2-ble-bridge setup"
            )
        self.user = resolve_user(self.options.user, self.host.sudo_user, self.host.user_exists)
        self.say(f"Setting up fido2-ble-bridge for the account {self.user}.")
        self.say("Each step skips what is already done. Press Ctrl-C to stop at any time.")
        self.prerequisites()
        current = self._read_config()
        address = self.pair(current)
        changed = self.configure(address, current, adapter=self.adapter)
        restarted = self.link(address)
        config = load_config(self.paths.config)
        self.service(config, config_changed=changed or restarted)
        node = self.fingerprint(config)
        node = self.register(node, config.device_name)
        tested = self.test_login(node)
        self.enable_pam(tested=tested)

    def _step(self, number: int, title: str) -> None:
        self.say(f"\n[{number}/{STEPS}] {title}")

    # Step 1

    def prerequisites(self) -> None:
        self._step(1, "Prerequisites")
        if not self.paths.unit.exists():
            raise SetupError(
                "the bridge is not installed as a service yet. Run sudo ./install.sh in the "
                "repository's linux/ directory first."
            )
        missing = self._missing()
        if missing:
            self._install(missing)
        bluetoothd = self._bluetoothd()
        bluez = parse_version(self._output([bluetoothd, "--version"])) if bluetoothd else None
        if bluez is not None and bluez < MIN_BLUEZ:
            raise SetupError(
                f"BlueZ {'.'.join(map(str, bluez))} is too old. The bridge needs 5.65 or newer, "
                "which reports whether a key is bonded (Ubuntu 24.04, Debian 13 and newer)."
            )
        systemd = parse_version(self._output(["systemctl", "--version"]))
        if systemd is not None and systemd[0] < MIN_SYSTEMD:
            raise SetupError(
                f"systemd {systemd[0]} is too old. The service needs 253 or newer (OpenFile=)."
            )
        found = []
        for name, version in (("BlueZ", bluez), ("systemd", systemd)):
            if version is None:
                self.say(f"  Could not tell the {name} version; going on.")
            else:
                found.append(f"{name} {'.'.join(map(str, version))}")
        found += ["uhid", "pam_u2f", "pamu2fcfg", "fido2-token"]
        if not self.paths.uhid.exists() and not self.runner.run(["modprobe", "uhid"]).ok:
            raise SetupError("cannot load the uhid kernel module, which the bridge needs.")
        # Checked first: without an adapter the Bluetooth service does not even start (its unit
        # needs /sys/class/bluetooth), so the advice to start it would not help.
        if not has_bluetooth_adapter(self.paths.bluetooth_class):
            raise SetupError(
                "no Bluetooth adapter found. Plug one in or switch it on (some computers have a "
                "BIOS or firmware setting for it), then run setup again."
            )
        if not self.runner.run(["systemctl", "is-active", "--quiet", "bluetooth"]).ok:
            raise SetupError(
                "the Bluetooth service is not running. Start it with "
                "sudo systemctl enable --now bluetooth, then run setup again."
            )
        self.say(f"  OK: {', '.join(found)}.")

    def _bluetoothd(self) -> str | None:
        for candidate in self.paths.bluetoothd:
            if candidate.exists():
                return str(candidate)
        return self.runner.which("bluetoothd")

    def _missing(self) -> list[str]:
        missing = []
        if self._bluetoothd() is None:
            missing.append("bluez")
        if pam.find_pam_u2f(self.paths.root) is None:
            missing.append("pam_u2f")
        for tool in ("pamu2fcfg", "fido2-token"):
            path = self.runner.which(tool)
            if path is None:
                missing.append(tool)
            else:
                self.tools[tool] = path
        return missing

    def _distro(self) -> str | None:
        for path in self.paths.os_release:
            with contextlib.suppress(OSError):
                return distro_family(path.read_text())
        return None

    def _install(self, missing: list[str]) -> None:
        self.say(f"  Missing: {', '.join(missing)}.")
        family = self._distro()
        if family is None:
            raise SetupError(
                "install BlueZ, pam_u2f with pamu2fcfg, and libfido2's fido2-token with your "
                "package manager, then run setup again."
            )
        command, packages = PACKAGES[family]
        names = sorted({packages[requirement] for requirement in missing})
        if family != "debian" or self.runner.which("apt-get") is None:
            raise SetupError(
                f"install them (sudo {command} {' '.join(names)}), then run setup again."
            )
        if not self.options.yes and not confirm(
            self.console, f"  Install {' '.join(names)} now with apt-get?", default=False
        ):
            raise SetupError(
                f"install them (sudo apt-get install {' '.join(names)}), then run setup again."
            )
        argv = ["apt-get", "install", "-y", *names]
        self.say(f"  Running: {' '.join(argv)}")
        if not self.runner.run(argv, interactive=True, capture=False, timeout=None).ok:
            raise SetupError(
                "apt-get could not install them. Run sudo apt-get update, then run setup again."
            )
        self.changes.append(
            Change(f"installed {' '.join(names)}", f"sudo apt-get remove {' '.join(names)}")
        )
        if still := self._missing():
            raise SetupError(f"still missing after installing: {', '.join(still)}.")

    def _output(self, argv: Sequence[str]) -> str:
        """What a version query printed; nothing when it failed, because an error message
        (`libglib-2.0.so.0: cannot open ...`) has numbers in it too."""
        result = self.runner.run(argv)
        return result.stdout if result.ok else ""

    def _read_config(self) -> Config | None:
        path = self.paths.config
        if not path.exists():
            return None
        try:
            return load_config(path)
        except ConfigError as exc:
            raise SetupError(
                f"the configuration is not valid ({exc}). Fix {path}, or delete it to start from "
                "scratch, then run setup again."
            ) from exc

    # Step 2

    def pair(self, current: Config | None) -> str:
        """Make sure BlueZ has a bond with the key; returns the key's address.

        One D-Bus connection serves the whole step, because BlueZ ties discovery and the
        pairing agent to it. Questions are asked between event-loop runs, where Ctrl-C works
        at once (inside a run, asyncio turns the first Ctrl-C into a task cancellation).
        """
        self._step(2, "Pair the key")
        configured = current.address if current else None
        if configured == PLACEHOLDER_ADDRESS:
            configured = None
        wanted = self.options.address or configured
        with asyncio.Runner() as loop:
            self._loop = loop
            try:
                bus = self._await(self.host.bus())
            except BluetoothError as exc:
                raise SetupError(f"Bluetooth is not available: {exc.text}.") from exc
            try:
                bluetooth = self._await(
                    BluezPairing.open(bus, current.adapter if current else None, key=wanted)
                )
                if bluetooth.adapter_count > 1:
                    # The bridge must use the adapter that holds the bond; left unset, it would
                    # take whichever powered adapter bleak happens to list first.
                    self.adapter = bluetooth.adapter
                    self.say(
                        f"  This computer has {bluetooth.adapter_count} Bluetooth adapters; "
                        f"using {bluetooth.adapter}."
                    )
                address = self._pair_with(bluetooth, wanted, configured)
                self.key_adapter = bluetooth.adapter
                self.bond_file = self._bond_file(bluetooth, address)
                return address
            except BluetoothError as exc:
                raise SetupError(f"Bluetooth: {exc}.") from exc
            finally:
                bus.disconnect()
                self._loop = None

    def _bond_file(self, bluetooth: BluezPairing, address: str) -> Path | None:
        directory = self._await(bluetooth.storage_dir())
        if directory is None or not _BT_ADDRESS.fullmatch(address):
            return None
        return self.paths.at(f"{BLUEZ_STORAGE}/{directory}/{address}/info")

    def _await(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        if self._loop is None:
            raise RuntimeError("only step 2 talks to BlueZ")
        return self._loop.run(coroutine)

    @property
    def _address_given(self) -> bool:
        """The key's address was given with --address on this run: the user named the device,
        so setup shows it but does not ask again."""
        return self.options.address is not None

    def _typed_yes(self, question: str) -> bool:
        """A question only a typed "yes" answers: Enter or "y" alone is not enough."""
        answer = self.console.ask(f"{question} Type yes to go on (anything else stops): ")
        return answer.strip().lower() == "yes"

    def _pair_with(
        self, bluetooth: BluezPairing, wanted: str | None, configured: str | None
    ) -> str:
        devices = self._await(bluetooth.devices())
        if wanted is not None:
            known = next((device for device in devices if device.address == wanted), None)
            if known is not None and known.has_bond:
                return self._use_bonded(bluetooth, known)
            if wanted == configured:
                self._warn_bond_lost(configured)
            if known is not None and known.paired:
                self.say(f"  BlueZ has an unfinished pairing with {wanted}: paired, but no bond.")
                self._remove_if_confirmed(bluetooth, known)
        else:
            bonded = [device for device in devices if device.fido and device.has_bond]
            if bonded:
                self.say("  These keys are already paired with this computer:")
                options = [f"{_describe(device)}  (paired)" for device in bonded]
                choice = choose(
                    self.console, "  Use one of them?", [*options, "No, pair a new key"]
                )
                if choice is None:
                    raise SetupError("no key chosen.")
                if choice < len(bonded):
                    return self._use_bonded(bluetooth, bonded[choice])
        return self._pair_new(bluetooth, wanted)

    def _warn_bond_lost(self, address: str) -> None:
        self.say(f"  Warning: the configured key {address} is not paired with this computer.")
        self.say("  If it was, and you did not remove the pairing yourself (with bluetoothctl, the")
        self.say("  desktop's Bluetooth settings or an earlier setup run), someone or something")
        self.say("  else did: BlueZ lets every local user remove pairings. A device that copies")
        self.say("  your key's address could now be waiting to be paired in its place. Pair only")
        self.say("  if you know why the pairing is gone, and with the key in your hand.")

    def _use_bonded(self, bluetooth: BluezPairing, device: BtDevice) -> str:
        if self._address_given:
            self.say(f"  Using {_describe(device)}, which BlueZ already has a bond with.")
        else:
            self.say(f"  BlueZ already has a bond with {_describe(device)}.")
            self.say("  A bond alone does not prove that it is your key: any local user can pair a")
            self.say("  device with this computer. Use it only if you paired it yourself.")
            if not self._typed_yes("  Use this device as your key?"):
                raise SetupError(
                    f"{device.address} was not used. If it is not your key, remove it "
                    f"(bluetoothctl remove {device.address}) and run setup again; to name your "
                    "key directly, use --address."
                )
        # BlueZ lists bonded devices while the adapter is off, too.
        self._ensure_powered(bluetooth)
        if not device.trusted:
            self._await(bluetooth.trust(device.path))
            self.changes.append(
                Change(
                    f"marked {device.address} as trusted in BlueZ",
                    f"bluetoothctl untrust {device.address}",
                )
            )
        self.say(f"  {device.address} is already paired and bonded; nothing to do.")
        return device.address

    def _remove_if_confirmed(self, bluetooth: BluezPairing, device: BtDevice) -> None:
        if not confirm(
            self.console, "  Remove that pairing and pair the key again?", default=False
        ):
            raise SetupError(
                "the existing pairing was left alone. To pair again, remove it "
                f"(bluetoothctl remove {device.address}) or answer yes next time."
            )
        self._await(bluetooth.remove(device.path))
        self.changes.append(
            Change(
                f"removed BlueZ's old pairing with {device.address}",
                "pair the key again with sudo fido2-ble-bridge setup",
            )
        )

    def _ensure_powered(self, bluetooth: BluezPairing) -> None:
        try:
            if self._await(bluetooth.power_on()):
                self.say("  Turned Bluetooth on.")
                self.changes.append(
                    Change("turned the Bluetooth adapter on", "bluetoothctl power off")
                )
        except BluetoothError as exc:
            if exc.name == BLOCKED:
                raise SetupError(
                    "Bluetooth is blocked (rfkill). Unblock it with sudo rfkill unblock bluetooth "
                    "or the wireless switch or key, then run setup again."
                ) from exc
            raise

    def _pair_new(self, bluetooth: BluezPairing, wanted: str | None) -> str:
        self._check_dual_boot()
        self._ensure_powered(bluetooth)
        if self._await(bluetooth.make_pairable()):
            self.changes.append(
                Change("made the Bluetooth adapter pairable", "bluetoothctl pairable off")
            )
        self.say(
            "  Put the key in pairing mode: hold its button about 5 s until the LED blinks fast."
        )
        self.say("  (A short press only wakes it. It must not be connected to a phone or another")
        self.say("  computer: a connected key does not advertise.)")
        self.console.ask("  Press Enter when the LED blinks fast: ")
        self.say(f"  Looking for keys in pairing mode (up to {self.timing.scan:g} s)...")
        self._await(bluetooth.start_discovery())
        try:
            device = self._find_key(bluetooth, wanted)
            if device.paired:
                self.say(
                    f"  BlueZ already has a pairing with {device.address}, but the key is in "
                    "pairing mode: it has probably lost its side (reset, or paired elsewhere)."
                )
                self._remove_if_confirmed(bluetooth, device)
                device = self._wait_for(bluetooth, device.address)
        finally:
            self._await(bluetooth.stop_discovery())
        return self._pair_device(bluetooth, device)

    def _check_dual_boot(self) -> None:
        if not any(path.is_dir() for path in self.paths.windows_boot):
            return
        self.say("  This computer also boots Windows. A key keeps one pairing per computer, and")
        self.say("  Windows and Linux share this computer's Bluetooth address, so pairing here")
        self.say("  replaces a pairing the key has with Windows. To use the key in both, copy the")
        self.say("  Windows pairing into BlueZ instead (README: Dual-boot with Windows).")
        if not confirm(self.console, "  Pair the key with Linux anyway?", default=False):
            raise SetupError(
                "the key was not paired. To share the Windows pairing, copy it into BlueZ as the "
                "README describes, then run setup again with --address."
            )

    def _advertising(self, bluetooth: BluezPairing, wanted: str | None) -> list[BtDevice]:
        return [
            device
            for device in self._await(bluetooth.devices())
            if device.fido and device.advertising and wanted in (None, device.address)
        ]

    def _find_key(self, bluetooth: BluezPairing, wanted: str | None) -> BtDevice:
        deadline = time.monotonic() + self.timing.scan
        settled: float | None = None
        while True:
            found = self._advertising(bluetooth, wanted)
            if found and settled is None:
                settled = time.monotonic() + (0 if wanted else self.timing.settle)
            now = time.monotonic()
            if (settled is not None and now >= settled) or now >= deadline:
                break
            time.sleep(self.timing.poll)
        if not found:
            where = f" at {wanted}" if wanted else ""
            raise SetupError(
                f"no key in pairing mode showed up{where}. Hold the key's button about 5 s until "
                "the LED blinks fast, keep it close, and make sure it is not connected to another "
                "device (a connected key does not advertise; turn Bluetooth off on your phone, or "
                "forget the key there). Then run setup again."
            )
        if wanted is not None and self._address_given:
            self.say(f"  Found {_describe(found[0])}, the address given with --address.")
            return found[0]
        if len(found) == 1:
            device = found[0]
            self.say(f"  Found one device in pairing mode: {_describe(device)}.")
        else:
            self.say("  Several keys are in pairing mode:")
            choice = choose(self.console, "  Which one?", [_describe(device) for device in found])
            if choice is None:
                raise SetupError("no key chosen.")
            device = found[choice]
        # Never paired without a typed yes, not even at the configured address: any device
        # nearby can claim to be a FIDO key and copy an address, and whatever is paired here
        # gets registered for logins in the next steps.
        self.say("  Any nearby device can claim to be a FIDO key, even with your key's address.")
        self.say("  Pair it only if your key's LED is blinking fast right now and nothing else")
        self.say("  nearby is pairing.")
        if not self._typed_yes(f"  Pair with {device.address}?"):
            raise SetupError(
                "no key was paired. If that was not your key, pair somewhere private, or give "
                "your key's address with --address."
            )
        return device

    def _wait_for(self, bluetooth: BluezPairing, address: str) -> BtDevice:
        deadline = time.monotonic() + self.timing.scan
        while time.monotonic() < deadline:
            for device in self._advertising(bluetooth, address):
                if not device.paired:
                    return device
            time.sleep(self.timing.poll)
        raise SetupError(
            f"{address} stopped advertising after its old pairing was removed. Put the key in "
            "pairing mode again, then run setup again."
        )

    def _pair_device(self, bluetooth: BluezPairing, device: BtDevice) -> str:
        self.say(
            f"  Pairing with {device.address}. If the key needs a passkey, you are asked here."
        )
        agent = PairingAgent(self.console, device.path)
        try:
            self._await(bluetooth.pair(device.path, agent, timeout=self.timing.pair))
        except BluetoothError as exc:
            if exc.name != ALREADY_EXISTS:
                raise SetupError(pairing_advice(exc)) from exc
        paired = self._await(bluetooth.device(device.path))
        if paired is None or not paired.has_bond:
            raise SetupError(
                "pairing finished, but BlueZ stored no bond for the key, so the bridge would "
                f"refuse it. Remove it (bluetoothctl remove {device.address}) and run setup again."
            )
        self._await(bluetooth.trust(paired.path))
        self._await(bluetooth.disconnect(paired.path))
        self.changes.append(
            Change(
                f"paired, bonded and trusted the key {paired.address} in BlueZ",
                f"bluetoothctl remove {paired.address}",
            )
        )
        if paired.address != device.address:
            self.say(
                f"  The key's permanent (identity) address is {paired.address}; it advertised as "
                f"{device.address}."
            )
        self.say(f"  Paired: {paired.address} is bonded and trusted.")
        return paired.address

    # Step 3

    def configure(
        self, address: str, current: Config | None, *, adapter: str | None = None
    ) -> bool:
        """Write `address`, and `adapter` if given and not configured yet, into the config;
        True if the config changed."""
        self._step(3, "Configuration")
        path = self.paths.config
        new_address = current is None or current.address != address
        new_adapter = None
        if adapter is not None and (current is None or current.adapter is None):
            new_adapter = adapter
        if not new_address and new_adapter is None:
            self.say(f"  {path} already names {address}; nothing to do.")
            return False
        text = path.read_text() if current else _NEW_CONFIG.format(address=address)
        if current is not None and new_address:
            text = set_address(text, address)
        if new_adapter is not None:
            text = set_adapter(text, new_adapter)
        try:
            written = parse_config(tomllib.loads(text))
        except (tomllib.TOMLDecodeError, ConfigError) as exc:
            raise SetupError(
                f"not writing {path}: with the new settings it would be invalid ({exc}). Fix the "
                "file, then run setup again."
            ) from exc
        if written.address != address:
            raise SetupError(f"not writing {path}: could not set its address line. Fix the file.")
        if new_adapter is not None and written.adapter != new_adapter:
            raise SetupError(f"not writing {path}: could not set its adapter line. Fix the file.")
        write_file(path, text)
        settings: list[str] = []
        undos: list[str] = []
        if new_address:
            settings.append(f'address = "{address}"')
            if current is not None:
                undos.append(f'put back address = "{current.address}"')
        if new_adapter is not None:
            settings.append(f'adapter = "{new_adapter}"')
            undos.append("delete the adapter line")
        undo = f"sudo rm {path}" if current is None else f"{' and '.join(undos)} in {path}"
        self.changes.append(Change(f"set {' and '.join(settings)} in {path}", undo))
        self.say(f"  Set {' and '.join(settings)} in {path}.")
        if new_adapter is not None:
            self.say("  (The key is bonded on that adapter, so the bridge must use it too.)")
        return True

    def link(self, address: str) -> bool:
        """Part of step 3: give the key's connections SUPERVISION_TIMEOUT in BlueZ's settings
        for it. True if Bluetooth was restarted for that, which the bridge must follow."""
        path = self.bond_file
        try:
            text = path.read_text() if path is not None else None
        except FileNotFoundError:
            text = None
        except OSError as exc:
            raise SetupError(f"cannot read {path}: {exc.strerror}.") from exc
        seconds = f"{SUPERVISION_TIMEOUT / 100:g} s"
        if path is None or text is None:
            self.say("  BlueZ keeps no settings file for the key where setup looks, so its")
            self.say("  connections keep the default supervision timeout of 0.42 s.")
            return False
        new = with_link_parameters(text)
        if new is None:
            self.say(f"  The key's connections already allow {seconds} without radio contact.")
            return False
        self.say("  By default Linux ends a Bluetooth LE connection after 0.42 s without radio")
        self.say("  contact, so a key that pauses longer, busy or a few metres away, drops a login")
        self.say(f"  midway. BlueZ can allow the key {seconds} instead ({path});")
        self.say("  it reads that when it starts.")
        if not confirm(
            self.console,
            f"  Allow {seconds} and restart Bluetooth now? (Bluetooth devices reconnect by "
            "themselves.)",
            default=True,
        ):
            self.say("  Left as it is; run setup again to change it.")
            return False
        old = link_parameters(text)
        write_file(path, new, mode=0o600)
        restore = (
            f"delete the [ConnectionParameters] group from {path}"
            if old is None
            else f"set [ConnectionParameters] in {path} back to "
            + ", ".join(f"{key}={value}" for key, value in old.items())
        )
        self.changes.append(
            Change(
                f"allowed the key {seconds} without radio contact in {path}",
                f"{restore}, then sudo systemctl restart bluetooth",
            )
        )
        self.say(f"  Allowed {seconds} in {path}.")
        result = self.runner.run(["systemctl", "restart", "bluetooth"])
        if not result.ok:
            details = _first_line(result.stderr) or "no details"
            raise SetupError(
                f"systemctl restart bluetooth failed: {details}. The setting takes effect once "
                "Bluetooth restarts: sudo systemctl restart bluetooth"
            )
        self._wait_for_bluetooth(address)
        self.say("  Restarted Bluetooth.")
        return True

    def _wait_for_bluetooth(self, address: str) -> None:
        """After a restart of bluetoothd: until it lists the key's bond on a powered adapter."""
        deadline = time.monotonic() + self.timing.bluetooth
        with asyncio.Runner() as loop:
            while not loop.run(self._bluetooth_ready(address)):
                if time.monotonic() >= deadline:
                    raise SetupError(
                        f"BlueZ did not list the key again within {self.timing.bluetooth:g} s of "
                        "restarting Bluetooth. See: systemctl status bluetooth; then run setup "
                        "again."
                    )
                time.sleep(self.timing.poll)

    async def _bluetooth_ready(self, address: str) -> bool:
        try:
            bus = await self.host.bus()
        except BluetoothError:
            return False
        try:
            bluetooth = await BluezPairing.open(bus, self.key_adapter, key=address)
            if not await bluetooth.powered():
                return False
            devices = await bluetooth.devices()
        except BluetoothError:
            return False
        finally:
            bus.disconnect()
        return any(device.address == address and device.has_bond for device in devices)

    # Step 4

    def service(self, config: Config, *, config_changed: bool) -> None:
        self._step(4, "Bridge service")
        enabled = self.runner.run(["systemctl", "is-enabled", "--quiet", UNIT]).ok
        active = self.runner.run(["systemctl", "is-active", "--quiet", UNIT]).ok
        if not (enabled and active):
            self._systemctl("enable", "--now", UNIT)
            self.changes.append(
                Change(
                    "enabled and started the fido2-ble-bridge service",
                    "sudo systemctl disable --now fido2-ble-bridge",
                )
            )
            self.say("  Enabled and started the fido2-ble-bridge service.")
        if active and config_changed:
            self._systemctl("restart", UNIT)
            self.say("  Restarted the service for the new configuration.")
        elif enabled and active:
            self.say("  The service is enabled and running; nothing to do.")
        self._check(config)

    def _systemctl(self, *args: str) -> None:
        result = self.runner.run(["systemctl", *args])
        if not result.ok:
            raise SetupError(
                f"systemctl {' '.join(args)} failed: {_first_line(result.stderr) or 'no details'}. "
                "See: journalctl -u fido2-ble-bridge -b"
            )

    def _check(self, config: Config) -> None:
        timeout = max(config.connect_timeout, self.timing.wake)
        self.say(
            "  Checking the key over Bluetooth. Wake the key now: press its button once. "
            f"(Waiting up to {timeout:g} s.)"
        )
        result = asyncio.run(self.host.check(config, timeout))
        if result.ok:
            self.say(f"  OK: {result.message}")
            return
        failed = f"the key check failed: {result.message}."
        remove = f"bluetoothctl remove {config.address}"
        if isinstance(result.error, KeyNotTrusted):
            raise SetupError(f"{failed} Remove the pairing ({remove}) and run setup again.")
        if isinstance(result.error, KeyNotReachable):
            raise SetupError(
                f"{failed} Wake the key (press its button once), keep it close, make sure it is "
                "not connected to another device, and run setup again. If the key was reset or "
                "paired with another computer since it was paired here, the pairing here is "
                f"stale: remove it ({remove}) and run setup again."
            )
        if isinstance(result.error, KeyUnsupported):
            raise SetupError(
                f"{failed} The bridge needs a key that offers FIDO2 over Bluetooth LE."
            )
        raise SetupError(f"{failed} For details run: fido2-ble-bridge -v check")

    # Step 5

    def fingerprint(self, config: Config) -> str:
        """Make sure the key can verify a fingerprint; returns the bridge's hidraw node."""
        self._step(5, "Fingerprint")
        node = self._wait_for_node(config.device_name)
        # Before anything is sent to it, and long before a PIN could be typed for it: the node
        # must be a FIDO device to libfido2, as the bridge's is.
        if node not in self._fido_devices():
            raise SetupError(
                f"{node} looks like the bridge's device, but fido2-token -L does not list it as "
                "a FIDO device. See what the service says: journalctl -u fido2-ble-bridge -b"
            )
        self.say(f"  The bridge's virtual FIDO device is {node}.")
        options = self._key_options(node)
        if "uv" in options:
            self.say("  A fingerprint is enrolled on the key; nothing to do.")
            return node
        self.say('  The key reports no enrolled fingerprint (its "uv" option is off).')
        token = self.tools["fido2-token"]
        if "clientPin" not in options:
            self.say("  Enrolling a fingerprint needs a PIN on the key, and it has none yet.")
            if not confirm(
                self.console, f"  Set a PIN now (fido2-token -S {node})?", default=False
            ):
                raise SetupError(
                    f"set a PIN (sudo fido2-token -S {node}, or the vendor's app), then run setup "
                    "again."
                )
            if not self.runner.run([token, "-S", node], interactive=True, capture=False).ok:
                raise SetupError(f"setting the PIN did not finish (sudo fido2-token -S {node}).")
            self.changes.append(
                Change(
                    "set a PIN on the key",
                    f"change it with fido2-token -C {node}; removing it needs a reset of the key",
                )
            )
        self.say(f"  You can enroll one here: sudo fido2-token -S -e {node}")
        self.say("  It asks for the key's PIN, then has you touch the sensor several times.")
        if not confirm(self.console, "  Enroll a fingerprint now?", default=False):
            raise SetupError(
                f"enroll a fingerprint (sudo fido2-token -S -e {node}, or the vendor's app), "
                "then run setup again."
            )
        if not self.runner.run([token, "-S", "-e", node], interactive=True, capture=False).ok:
            raise SetupError(
                f"enrolling did not finish. Try it by hand (sudo fido2-token -S -e {node}), then "
                "run setup again."
            )
        if "uv" not in self._key_options(node):
            raise SetupError("the key still reports no enrolled fingerprint.")
        self.changes.append(
            Change(
                "enrolled a fingerprint on the key",
                f"list them with fido2-token -L -e {node}, delete one with "
                f"fido2-token -D -e -i ID {node}",
            )
        )
        return node

    def _wait_for_node(self, name: str) -> str:
        deadline = time.monotonic() + self.timing.node
        while (node := self._find_node(name)) is None:
            if time.monotonic() >= deadline:
                raise SetupError(
                    f"the bridge's virtual FIDO device ({name}) did not appear. See what the "
                    "service says: journalctl -u fido2-ble-bridge -b"
                )
            time.sleep(self.timing.poll)
        return node

    def _find_node(self, name: str) -> str | None:
        try:
            return find_hidraw_node(self.paths.hidraw_class, name)
        except AmbiguousDevice as exc:
            raise SetupError(
                f"{exc}. Only the bridge should make a device with that name: stop whatever else "
                "made one, or set another device_name in the configuration, then run setup again."
            ) from exc

    def _key_options(self, node: str) -> set[str]:
        self.say(
            "  Wake the key: press its button once. Reading its settings through the bridge..."
        )
        result = self.runner.run([self.tools["fido2-token"], "-I", node], timeout=90)
        options = parse_options(result.stdout) if result.ok else None
        if options is None:
            detail = _first_line(result.stderr) or "it did not answer as a FIDO2 key"
            raise SetupError(
                f"could not read the key's settings through the bridge ({detail}). Wake the key "
                "(press its button once) and run setup again."
            )
        return options

    # Step 6

    def register(self, node: str, device_name: str) -> str:
        """Register the key with pamu2fcfg (and a backup key, if wanted). Nothing is written
        yet: step 7 saves the new credentials once a login with them worked. Returns the
        bridge's hidraw node, which changes when the bridge restarts for a backup key."""
        self._step(6, f"Register the key for {self.user}")
        path = self.paths.mappings
        existing = mapping_lines(self._mappings_text(), self.user)
        if existing:
            count = credential_count(existing[-1])
            if len(existing) == 1:
                self.say(f"  {self.user} already has {count} key(s) registered in {path}.")
                replacing = "that line"
            else:
                self.say(f"  {self.user} has {len(existing)} lines in {path}. pam_u2f uses only")
                self.say(f"  the last one, which has {count} key(s).")
                replacing = f"all {len(existing)} lines"
            if not confirm(
                self.console,
                f"  Register this key again, replacing {replacing} and the {count} key(s) on it "
                "(backup keys too)?",
                default=False,
            ):
                self.say("  Keeping the existing registration.")
                return self._offer_backup(node, device_name)
        self._only_device(node, "pamu2fcfg registers the first one it finds")
        self.say("  Wake the key: press its button once. When it lights up, touch the fingerprint")
        self.say("  sensor (pamu2fcfg runs once; it asks for the key's PIN only if it needs it).")
        self.say("  It must be your own key that lights up and reads your finger. If setup moves")
        self.say("  on without that, the paired device is not your key: press Ctrl-C.")
        self.new_entry = self._pamu2fcfg([], prefix=f"{self.user}:")
        self.registered = True
        self.say(f"  Registered the key for {self.user}. Step 7 saves the registration once a")
        self.say("  login with it worked.")
        return self._offer_backup(node, device_name)

    def _mappings_text(self) -> str:
        path = self.paths.mappings
        return path.read_text() if path.exists() else ""

    def _fido_devices(self) -> list[str]:
        result = self.runner.run([self.tools["fido2-token"], "-L"])
        if not result.ok:
            raise SetupError(
                f"fido2-token -L failed: {_first_line(result.stderr) or 'no details'}."
            )
        return [
            line.split(":", 1)[0].strip() for line in result.stdout.splitlines() if line.strip()
        ]

    def _only_device(self, node: str, why: str) -> None:
        devices = self._fido_devices()
        if devices == [node]:
            return
        if node not in devices:
            raise SetupError(f"fido2-token -L does not list the bridge ({node}).")
        others = ", ".join(device for device in devices if device != node)
        self.say(f"  Other FIDO devices are attached ({others}).")
        self.say(f"  {why}, so unplug them now.")
        self.console.ask("  Press Enter when they are unplugged: ")
        if self._fido_devices() != [node]:
            raise SetupError(
                "other FIDO devices are still attached. Unplug them and run setup again."
            )

    def _pamu2fcfg(self, extra: list[str], *, prefix: str) -> str:
        argv = [self.tools["pamu2fcfg"], "-u", self.user, "-o", pam.ORIGIN, "-i", pam.ORIGIN, "-V"]
        result = self.runner.run([*argv, *extra], interactive=True, timeout=None)
        if not result.ok:
            raise SetupError(
                f"registering failed (pamu2fcfg exited with status {result.returncode}); nothing "
                "was written. If the key did not recognise your finger, check which finger is "
                "enrolled before trying again: some keys lock or reset themselves after repeated "
                "failed matches. Then run setup again; it asks for the fingerprint once."
            )
        entry = result.stdout.strip()
        if not _valid_mapping(entry, prefix):
            raise SetupError("pamu2fcfg printed something unexpected; nothing was written.")
        return entry

    def _offer_backup(self, node: str, device_name: str) -> str:
        if not confirm(
            self.console,
            f"  Also register a backup key for {self.user} (another FIDO2 key with its own "
            "fingerprint sensor, plugged in over USB)?",
            default=False,
        ):
            return node
        self.say("  Stopping the bridge for a moment, so that only the backup key is visible.")
        self._systemctl("stop", UNIT)
        try:
            self._register_backup()
        finally:
            self._systemctl("start", UNIT)
        self.say("  Unplug the backup key now: the login test uses the Bluetooth key alone.")
        # systemctl start returns before the bridge has made its device, whose number can differ.
        return self._wait_for_node(device_name)

    def _register_backup(self) -> None:
        self.console.ask("  Plug in the backup key, then press Enter: ")
        devices = self._fido_devices()
        if len(devices) != 1:
            self.say(f"  Expected exactly one FIDO device, found {len(devices)}; skipping it.")
            return
        info = self.runner.run([self.tools["fido2-token"], "-I", devices[0]], timeout=30)
        options = parse_options(info.stdout) if info.ok else None
        if options is None or "uv" not in options:
            self.say('  That key reports no enrolled fingerprint (no "uv" option). The PAM line')
            self.say("  needs the key to verify a fingerprint itself, so it could not log in;")
            self.say("  skipping it.")
            return
        self.say("  Touch the backup key's fingerprint sensor when it lights up.")
        try:
            entry = self._pamu2fcfg(["-n"], prefix=":")
        except SetupError as exc:
            self.say(f"  The backup key was not registered: {exc}")
            return
        self.backup_entries.append(entry)
        self.say("  Backup key registered; step 7 saves it together with the rest.")

    # Step 7

    def test_login(self, node: str) -> bool:
        """One PAM authentication outside /etc/pam.d, on exactly the authfile text that is saved
        afterwards, with the pam_u2f line step 8 would enable, and with the bridge as the only
        FIDO device. Saves step 6's registration once it passed. True if it ran and passed."""
        self._step(7, "Test a login")
        path = self.paths.mappings
        if not self.registered and (self.options.no_pam or self._pam_enabled()):
            self.say("  The Bluetooth key's registration did not change and there is nothing to")
            self.say("  enable; skipped.")
            self._save_registration()
            return False
        if not self.host.pam.available():
            self.say("  This system's PAM cannot run a test stack outside /etc/pam.d (that needs")
            self.say("  Linux-PAM 1.4 or newer). Test by hand instead: see the README's manual")
            self.say("  setup (pamtester).")
            self._save_registration()
            return False
        current, merged = self._pending_mappings()
        if mapping_line(merged, self.user) is None:
            raise SetupError(f"{self.user} has no key registered in {path}; run setup again.")
        module, arguments = self._test_line()
        # A backup key in the line could otherwise pass the test for the Bluetooth key.
        self._only_device(node, "The login test must use the Bluetooth key alone")
        self.say(f"  One real login attempt for {self.user} through pam_u2f, using a temporary PAM")
        self.say("  stack outside /etc/pam.d. Wake the key: press its button once. Touch the")
        self.say("  fingerprint sensor when asked. If the test passes without your own key reading")
        self.say("  your finger, the paired device is not your key: do not enable it in step 8.")
        with tempfile.TemporaryDirectory(prefix="fido2-ble-bridge-setup-") as confdir:
            authfile = Path(confdir, "u2f_mappings")
            write_file(authfile, merged)  # root's, which pam_u2f requires (or the user's)
            swapped = [
                f"authfile={authfile}" if argument.startswith("authfile=") else argument
                for argument in arguments
            ]
            stack = f"auth required {module} {' '.join(swapped)}\n"
            Path(confdir, PAM_TEST_SERVICE).write_text(stack)
            try:
                result = self.host.pam.authenticate(
                    Path(confdir),
                    PAM_TEST_SERVICE,
                    self.user,
                    lambda text: self.say(f"  pam_u2f: {text}"),
                )
            except pam.PamError as exc:
                raise SetupError(f"the login test could not run: {exc}.") from exc
        if not result.ok:
            raise SetupError(
                f"the login test failed ({result.description}). Nothing was saved: {path} and "
                "PAM are as they were. If the key did not recognise your finger, check which "
                "finger is enrolled before trying again: some keys lock or reset themselves after "
                "repeated failed matches. Then run setup again; it tests once."
            )
        self.say("  Login test passed.")
        self._save_registration(tested=current)
        return True

    def _test_line(self) -> tuple[str, list[str]]:
        """pam_u2f's module and arguments for the login test: the installed PAM profile's own
        when step 8 would enable that profile (refused if weaker than the shipped one), else
        those of the line the manual instructions give."""
        self.tested_profile = None
        if self.options.no_pam or not self._profile_in_use():
            return "pam_u2f.so", pam.u2f_arguments(DEFAULT_MAPPINGS_PATH).split()
        text = self.paths.pam_profile.read_text()
        module, arguments = self._checked_profile(text)
        self.tested_profile = text
        return module, arguments

    def _profile_in_use(self) -> bool:
        """Whether step 8 would enable the PAM profile (else it prints the line to add)."""
        return self.runner.which("pam-auth-update") is not None and self.paths.pam_profile.exists()

    def _checked_profile(self, text: str) -> tuple[str, list[str]]:
        """The profile's pam_u2f module and arguments; SetupError unless the line requires the
        fingerprint, reads the authfile setup writes and has nothing that weakens it."""
        profile = self.paths.pam_profile
        lines = set(pam.profile_u2f_lines(text))
        if len(lines) != 1:
            raise SetupError(
                f"{profile} should have one pam_u2f line (the same in Auth and Auth-Initial), "
                f"but has {len(lines)} different ones. Restore it from the project's "
                "linux/packaging/pam-configs/, then run setup again."
            )
        module, *arguments = next(iter(lines))
        defaults = self._pam_u2f_defaults()
        problems = pam.u2f_option_problems([*defaults, *arguments], DEFAULT_MAPPINGS_PATH)
        if problems:
            where = f"pam_u2f line (with {self.paths.pam_u2f_conf})" if defaults else "pam_u2f line"
            raise SetupError(
                f"setup does not test or enable {profile}: its {where} has {', '.join(problems)}. "
                "Setup only enables a line that requires the fingerprint (userverification=1), "
                f"reads {DEFAULT_MAPPINGS_PATH}, and has none of alwaysok, nouserok, openasuser, "
                "expand or options setup does not know. Restore the profile from the project's "
                "linux/packaging/pam-configs/ (or fix it), then run setup again."
            )
        return module, arguments

    def _pam_u2f_defaults(self) -> list[str]:
        try:
            return pam.config_file_arguments(self.paths.pam_u2f_conf.read_text())
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise SetupError(f"cannot read {self.paths.pam_u2f_conf}: {exc.strerror}.") from exc

    def _pending_mappings(self) -> tuple[str, str]:
        """The authfile's text now, and with step 6's new credentials merged in: all of the
        user's lines replaced by the new one, backup keys added to the line that counts."""
        text = self._mappings_text()
        merged = text
        if self.new_entry is not None:
            merged = merge_mapping(merged, self.user, self.new_entry)
        for entry in self.backup_entries:
            merged = merge_mapping(merged, self.user, entry, append=True)
        return text, merged

    def _save_registration(self, *, tested: str | None = None) -> None:
        """Write step 6's new credentials into the authfile, keeping a copy of the old file.
        `tested` is the authfile's text when the login test ran, so that exactly the tested
        result is saved."""
        if self.new_entry is None and not self.backup_entries:
            return
        path = self.paths.mappings
        text, merged = self._pending_mappings()
        if tested is not None and text != tested:
            raise SetupError(
                f"{path} changed while the login test ran, so the tested registration was not "
                "saved. Run setup again."
            )
        keys: list[str] = []
        if self.new_entry is not None:
            keys.append("the key")
        if self.backup_entries:
            count = len(self.backup_entries)
            keys.append("a backup key" if count == 1 else f"{count} backup keys")
        if mapping_line(text, self.user) is None:
            undo = f"delete the line starting with {self.user}: from {path}"
        else:
            backup = path.with_name(path.name + ".bak")
            write_file(backup, text)
            undo = f"sudo cp {backup} {path}"
        write_file(path, merged)
        self.new_entry = None
        self.backup_entries = []
        self.changes.append(
            Change(f"registered {' and '.join(keys)} for {self.user} in {path}", undo)
        )
        self.say(f"  Saved the registration in {path}.")

    # Step 8

    def _pam_enabled(self) -> bool:
        try:
            text = self.paths.common_auth.read_text()
        except OSError:
            return False
        marker = f"authfile={DEFAULT_MAPPINGS_PATH}"
        return any(
            "pam_u2f.so" in line and marker in line and not line.lstrip().startswith("#")
            for line in text.splitlines()
        )

    def enable_pam(self, *, tested: bool) -> None:
        self._step(8, "Use the key for logins (PAM)")
        enable_later = "sudo pam-auth-update --enable fido2-ble-bridge"
        if self.options.no_pam:
            self.say(f"  Skipped (--no-pam). To enable it later: {enable_later}")
            return
        if self._pam_enabled():
            self.say(f"  Already enabled in {self.paths.common_auth}; nothing to do.")
            return
        if not tested:
            self.say("  Not enabled, because no login test passed in this run. Run setup again")
            self.say("  to test and enable it.")
            return
        if not self._profile_in_use():
            self._manual_pam()
            return
        profile = self.paths.pam_profile
        text = profile.read_text()
        self._checked_profile(text)
        if text != self.tested_profile:
            raise SetupError(
                f"{profile} is not the profile whose pam_u2f line the login test used (it changed "
                "since, or the test used another line), so it is not enabled. Run setup again."
            )
        self.say("  This puts the key in front of the password in /etc/pam.d/common-auth for the")
        self.say("  login screen and lock screens, and for sudo and the console's login when they")
        self.say("  run in a session at this computer. su, polkit (pkexec, admin dialogs) and SSH")
        self.say("  keep asking for the password, and so does sudo in an SSH session.")
        self.say("  If the key is away or fails, you get the password prompt as before.")
        self.say("  First open a root shell in another terminal (sudo -i) and keep it open until")
        self.say("  you have tested a fresh login with the key.")
        answer = self.console.ask("  Type yes to enable it now (anything else skips): ")
        if answer.strip().lower() != "yes":
            self.say(f"  Not enabled. To do it later: {enable_later}")
            return
        result = self.runner.run(
            ["pam-auth-update", "--enable", PAM_PROFILE],
            env={"DEBIAN_FRONTEND": "noninteractive"},
        )
        if not result.ok or not self._pam_enabled():
            said = _first_line(result.stdout + "\n" + result.stderr)
            raise SetupError(
                f"pam-auth-update did not enable the profile ({said or 'no details'}). It leaves "
                "/etc/pam.d/common-auth alone if that file was edited by hand, and setup never "
                f"forces it. Merge the change yourself, then run: {enable_later}"
            )
        self.changes.append(
            Change(
                "enabled the key for local logins (PAM profile fido2-ble-bridge, in common-auth)",
                "sudo pam-auth-update --disable fido2-ble-bridge",
            )
        )
        self.say("  Enabled. Now, in a new terminal, run: sudo -k; sudo true")
        self.say(
            "  It should ask for your fingerprint. Then lock the screen and unlock it with the"
        )
        self.say("  key. Keep the root shell open until both work.")
        self.say("  To undo: sudo pam-auth-update --disable fido2-ble-bridge")

    def _manual_pam(self) -> None:
        line = f"auth sufficient pam_u2f.so {pam.u2f_arguments(DEFAULT_MAPPINGS_PATH)}"
        check = f"auth [success=ignore default=1] pam_exec.so quiet {pam.LOCAL_SESSION_CHECK}"
        self.say("  This system has no pam-auth-update, so setup does not edit PAM files. Add this")
        self.say("  line before the password line (pam_unix) in the PAM file of your display")
        self.say("  manager or screen locker (gdm-password, sddm, lightdm, ...):")
        self.say(f"    {line}")
        self.say("  For sudo (/etc/pam.d/sudo), add the same line with this one right in front of")
        self.say("  it, so that sudo skips the key unless it runs in a session at this computer:")
        self.say(f"    {check}")
        self.say("  Do not add the key to su or polkit-1 without that check: anyone on this")
        self.say("  computer, or logged in over SSH, could then make your key ask for your")
        self.say("  fingerprint, and would be logged in as you if you touched it.")
        self.say("  Keep a root shell open while you test it. To undo, delete the lines.")

    # Summary

    def _summary(self) -> None:
        self.say("\nSummary")
        if not self.changes:
            self.say("  Nothing on this system was changed.")
            return
        self.say("  Changed on this system, and how to undo each change:")
        for change in self.changes:
            self.say(f"  - {change.what}")
            self.say(f"      undo: {change.undo}")


def run_setup(options: SetupOptions, host: Host | None = None) -> int:
    return Setup(options, host or Host(console=TerminalConsole())).run()
