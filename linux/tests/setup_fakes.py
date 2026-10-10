"""Fakes for `fido2-ble-bridge setup`: BlueZ on a fake D-Bus, commands, the terminal and PAM.

FakeBluez answers the D-Bus messages setup's BlueZ code sends (the real BluezPairing runs
against it) and calls back into the exported pairing agent the way bluetoothd does.
"""

from __future__ import annotations

import asyncio
import inspect
import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dbus_fast import Message, MessageType, Variant
from dbus_fast.errors import DBusError
from dbus_fast.service import ServiceInterface

from fido2_ble_bridge.ble_link import FIDO_SERVICE_UUID
from fido2_ble_bridge.pairing import AgentInterface
from fido2_ble_bridge.pam import ORIGIN, PAM_AUTH_ERR, PAM_SUCCESS, PamResult
from fido2_ble_bridge.setup_wizard import Completed, Paths
from fido2_ble_bridge.uhid import BRIDGE_PHYS

PROJECT = Path(__file__).resolve().parents[1]
ADAPTER_PATH = "/org/bluez/hci0"
ADAPTER = "org.bluez.Adapter1"
DEVICE = "org.bluez.Device1"
NODE = "/dev/hidraw5"
USER = "alice"
KEY = "11:22:33:44:55:66"
MAPPING = f"{USER}:S2V5SGFuZGxl,UHVibGljS2V5,es256,+presence+verification"

_SIGNATURES = {
    "Address": "s",
    "Name": "s",
    "Paired": "b",
    "Bonded": "b",
    "Trusted": "b",
    "UUIDs": "as",
    "RSSI": "n",
    "Powered": "b",
    "Pairable": "b",
}


def device_path(address: str) -> str:
    return f"{ADAPTER_PATH}/dev_{address.replace(':', '_')}"


class FakeBluez:
    """bluetoothd's D-Bus API as setup uses it, as one fake system-bus connection."""

    def __init__(self, *, powered: bool = True, pairable: bool = True) -> None:
        self.objects: dict[str, dict[str, dict[str, Any]]] = {
            ADAPTER_PATH: {ADAPTER: {"Powered": powered, "Pairable": pairable}}
        }
        self.calls: list[tuple[str, str]] = []
        """(member, object path) of every method call, in order."""
        self.exported: dict[str, ServiceInterface] = {}
        self.agents: dict[str, str] = {}
        """Registered agent path -> capability."""
        self.in_pairing_mode: set[str] = set()
        """Addresses that advertise while discovery runs."""
        self.discovering = False
        self.discovery_filter: dict[str, Any] | None = None
        self.pair_error: str | None = None
        self.pair_hangs = False
        self.asks_passkey = False
        self.passkeys: list[int] = []
        self.identity: dict[str, str] = {}
        """Address -> the identity address it changes to once paired (a resolvable one)."""
        self.power_error: str | None = None
        self.disconnected = False
        self._serial = 0

    # Test setup

    def add_device(
        self,
        address: str,
        *,
        paired: bool = False,
        bonded: bool = False,
        trusted: bool = False,
        name: str = "Test Key",
    ) -> str:
        path = device_path(address)
        self.objects[path] = {
            DEVICE: {
                "Address": address,
                "Name": name,
                "Paired": paired,
                "Bonded": bonded,
                "Trusted": trusted,
                "UUIDs": [FIDO_SERVICE_UUID],
            }
        }
        return path

    def device(self, address: str) -> dict[str, Any]:
        for interfaces in self.objects.values():
            props = interfaces.get(DEVICE)
            if props is not None and props["Address"] == address:
                return props
        raise KeyError(address)

    def members(self) -> list[str]:
        return [member for member, _path in self.calls]

    # The bus

    async def call(self, msg: Message) -> Message | None:
        assert not self.disconnected, "call on a closed bus"
        assert msg.member is not None and msg.path is not None
        self.calls.append((msg.member, msg.path))
        handler = getattr(self, f"_{msg.member}", None)
        if handler is None:
            raise AssertionError(f"unexpected D-Bus call {msg.interface}.{msg.member}")
        try:
            result = handler(msg.path, *msg.body)
            if asyncio.iscoroutine(result):
                result = await result
        except DBusError as exc:
            return self._error(exc.type, exc.text)
        if isinstance(result, Message):
            return result
        return self._reply()

    def export(self, path: str, interface: ServiceInterface) -> None:
        self.exported[path] = interface

    def unexport(self, path: str, interface: ServiceInterface | str | None = None) -> None:
        del self.exported[path]

    def disconnect(self) -> None:
        self.disconnected = True

    def _reply(self, signature: str = "", body: list[Any] | None = None) -> Message:
        self._serial += 1
        return Message(
            message_type=MessageType.METHOD_RETURN,
            reply_serial=self._serial,
            signature=signature,
            body=body or [],
        )

    def _error(self, name: str, text: str) -> Message:
        self._serial += 1
        return Message(
            message_type=MessageType.ERROR,
            reply_serial=self._serial,
            error_name=name,
            signature="s",
            body=[text],
        )

    @staticmethod
    def _variants(props: Mapping[str, Any]) -> dict[str, Variant]:
        return {name: Variant(_SIGNATURES[name], value) for name, value in props.items()}

    def _show_advertisers(self) -> None:
        # BlueZ creates a device object the moment it hears an advertisement.
        for address in self.in_pairing_mode:
            try:
                props = self.device(address)
            except KeyError:
                props = self.objects[self.add_device(address)][DEVICE]
            props["RSSI"] = -50

    # org.freedesktop.DBus.ObjectManager and Properties

    def _GetManagedObjects(self, path: str) -> Message:
        assert path == "/"
        if self.discovering:
            self._show_advertisers()
        objects = {
            object_path: {name: self._variants(props) for name, props in interfaces.items()}
            for object_path, interfaces in self.objects.items()
        }
        return self._reply("a{oa{sa{sv}}}", [objects])

    def _GetAll(self, path: str, interface: str) -> Message:
        return self._reply("a{sv}", [self._variants(self.objects[path][interface])])

    def _Set(self, path: str, interface: str, name: str, value: Variant) -> None:
        if (interface, name) == (ADAPTER, "Powered") and self.power_error:
            raise DBusError(self.power_error, "blocked")
        self.objects[path][interface][name] = value.value

    # org.bluez.AgentManager1

    def _RegisterAgent(self, path: str, agent: str, capability: str) -> None:
        assert agent in self.exported, "agent registered before it was exported"
        if agent in self.agents:
            raise DBusError("org.bluez.Error.AlreadyExists", "Already Exists")
        self.agents[agent] = capability

    def _UnregisterAgent(self, path: str, agent: str) -> None:
        if self.agents.pop(agent, None) is None:
            raise DBusError("org.bluez.Error.DoesNotExist", "Does Not Exist")

    # org.bluez.Adapter1

    def _SetDiscoveryFilter(self, path: str, discovery_filter: dict[str, Variant]) -> None:
        self.discovery_filter = {key: variant.value for key, variant in discovery_filter.items()}

    def _StartDiscovery(self, path: str) -> None:
        self.discovering = True

    def _StopDiscovery(self, path: str) -> None:
        self.discovering = False
        for interfaces in self.objects.values():
            interfaces.get(DEVICE, {}).pop("RSSI", None)

    def _RemoveDevice(self, path: str, device: str) -> None:
        del self.objects[device]

    # org.bluez.Device1

    async def _Pair(self, path: str) -> None:
        props = self.objects[path][DEVICE]
        assert self.agents, "Pair() without an agent registered on this connection"
        if self.pair_hangs:
            await asyncio.sleep(3600)
        if self.asks_passkey:
            (agent_path,) = self.agents
            agent = self.exported[agent_path]
            assert isinstance(agent, AgentInterface)
            # What bluetoothd's call reaches: the method body dbus-fast dispatches to.
            request = inspect.unwrap(AgentInterface.RequestPasskey)
            try:
                self.passkeys.append(request(agent, path))
            except DBusError as exc:
                raise DBusError("org.bluez.Error.AuthenticationCanceled", exc.text) from exc
        if self.pair_error:
            raise DBusError(self.pair_error, "pairing failed")
        props["Paired"] = props["Bonded"] = True
        props["Address"] = self.identity.get(props["Address"], props["Address"])

    def _CancelPairing(self, path: str) -> None:
        pass

    def _Disconnect(self, path: str) -> None:
        pass


Response = Completed | Callable[[list[str]], Completed]


class FakeRunner:
    """Commands by name: argv[0] is reduced to its file name, then matched by prefix."""

    def __init__(self) -> None:
        self.tools = {"pamu2fcfg", "fido2-token", "pam-auth-update", "apt-get"}
        self.calls: list[list[str]] = []
        self.options: list[dict[str, Any]] = []
        self._handlers: list[tuple[tuple[str, ...], Response]] = []

    def on(self, *prefix: str, result: Response) -> None:
        """Answer commands starting with `prefix`; later registrations win."""
        self._handlers.insert(0, (prefix, result))

    def ran(self, *prefix: str) -> list[list[str]]:
        return [argv for argv in self.calls if tuple(argv[: len(prefix)]) == prefix]

    def which(self, name: str) -> str | None:
        return f"/usr/bin/{name}" if name in self.tools else None

    def run(
        self,
        argv: Sequence[str],
        *,
        interactive: bool = False,
        capture: bool = True,
        env: Mapping[str, str] | None = None,
        timeout: float | None = 60.0,
    ) -> Completed:
        command = [os.path.basename(argv[0]), *argv[1:]]
        self.calls.append(command)
        self.options.append({"interactive": interactive, "capture": capture, "env": env})
        for prefix, result in self._handlers:
            if tuple(command[: len(prefix)]) == prefix:
                return result(command) if callable(result) else result
        raise AssertionError(f"unexpected command: {command}")


class ScriptedConsole:
    """Answers questions from a list, in order; an unexpected question fails the test."""

    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.lines: list[str] = []
        self.prompts: list[str] = []

    def say(self, text: str = "") -> None:
        self.lines.append(text)

    def ask(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.answers:
            raise AssertionError(f"unexpected question: {prompt!r}")
        return self.answers.pop(0)

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


class FakePam:
    def __init__(self, *, available: bool = True, succeeds: bool = True) -> None:
        self.is_available = available
        self.succeeds = succeeds
        self.calls: list[tuple[str, str, str]] = []
        """(service, user, the stack file's text) per authentication."""
        self.authfiles: list[str] = []
        """The text of the authfile the stack names, per authentication."""

    def available(self) -> bool:
        return self.is_available

    def authenticate(
        self, confdir: Path, service: str, user: str, on_message: Callable[[str], None]
    ) -> PamResult:
        stack = (confdir / service).read_text()
        self.calls.append((service, user, stack))
        authfile = re.search(r"authfile=(\S+)", stack)
        self.authfiles.append(Path(authfile.group(1)).read_text() if authfile else "")
        on_message("Please touch the device.")
        if self.succeeds:
            return PamResult(PAM_SUCCESS, "Success", ["Please touch the device."])
        return PamResult(PAM_AUTH_ERR, "Authentication failure", ["Please touch the device."])


def add_hidraw(
    root: Path,
    name: str,
    number: int = 5,
    *,
    virtual: bool = True,
    bus: str = "0003",
    phys: str = BRIDGE_PHYS,
    uniq: str = "",
) -> None:
    """A hidraw node as sysfs shows it: /sys/class/hidraw/hidrawN links into the device tree.
    By default the bridge's own: a uhid device on the USB bus with the bridge's phys."""
    parent = "virtual/misc/uhid" if virtual else "pci0000:00/0000:00:14.0/usb1/1-1/1-1:1.0"
    hid = root / "sys/devices" / parent / f"{bus}:0000:0000.{number:04X}"
    node = hid / "hidraw" / f"hidraw{number}"
    node.mkdir(parents=True)
    (hid / "uevent").write_text(
        f"DRIVER=hid-generic\nHID_ID={bus}:00000000:00000000\nHID_NAME={name}\n"
        f"HID_PHYS={phys}\nHID_UNIQ={uniq}\nMODALIAS=hid:b{bus}g0001v00000000p00000000\n"
    )
    (node / "device").symlink_to(os.path.relpath(hid, node))
    links = root / "sys/class/hidraw"
    links.mkdir(parents=True, exist_ok=True)
    (links / f"hidraw{number}").symlink_to(os.path.relpath(node, links))


def make_root(root: Path) -> Paths:
    """A freshly installed system: unit, example config, BlueZ, pam_u2f, uhid, Ubuntu."""
    paths = Paths(root)
    files = {
        paths.unit: "[Service]\n",
        paths.config: (PROJECT / "packaging" / "config.toml.example").read_text(),
        paths.pam_profile: (PROJECT / "packaging" / "pam-configs" / "fido2-ble-bridge").read_text(),
        paths.common_auth: "auth\t[success=1 default=ignore]\tpam_unix.so nullok\n",
        paths.uhid: "",
        paths.at("/usr/libexec/bluetooth/bluetoothd"): "",
        paths.at("/usr/lib/x86_64-linux-gnu/security/pam_u2f.so"): "",
        paths.at("/etc/os-release"): 'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\n',
    }
    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    (paths.bluetooth_class / "hci0").mkdir(parents=True)
    return paths


def token_info(options: str = "rk, up, uv, noplat, clientPin") -> str:
    """What `fido2-token -I` prints for a CTAP2 key (abridged)."""
    return (
        "proto: 0x02\nmajor: 0x01\nminor: 0x00\nbuild: 0x00\ncaps: 0x05 (wink, cbor, msg)\n"
        "version strings: U2F_V2, FIDO_2_0\nextension strings: credProtect, hmac-secret\n"
        f"aaguid: {'00' * 16}\noptions: {options}\n"
    )


@dataclass
class SystemState:
    """What the fake commands change: services, PAM, the installed tools."""

    service_enabled: bool = False
    service_active: bool = False
    pam_auth_update_works: bool = True
    devices: list[str] = field(default_factory=lambda: [NODE])


def healthy_runner(paths: Paths, state: SystemState) -> FakeRunner:
    """Answers for an Ubuntu 24.04-like system where every command works."""
    runner = FakeRunner()
    ok = Completed(0)
    runner.on("bluetoothd", "--version", result=Completed(0, "5.72\n"))
    runner.on("systemctl", "--version", result=Completed(0, "systemd 255 (255.4-1ubuntu8)\n+PAM\n"))
    runner.on("systemctl", "is-active", "--quiet", "bluetooth", result=ok)
    runner.on("modprobe", "uhid", result=ok)

    def is_enabled(_argv: list[str]) -> Completed:
        return Completed(0 if state.service_enabled else 1)

    def is_active(_argv: list[str]) -> Completed:
        return Completed(0 if state.service_active else 3)

    def enable_now(_argv: list[str]) -> Completed:
        state.service_enabled = state.service_active = True
        return ok

    def stop(_argv: list[str]) -> Completed:
        state.service_active = False
        return ok

    def start(_argv: list[str]) -> Completed:
        state.service_active = True
        return ok

    def fido_devices(_argv: list[str]) -> Completed:
        return Completed(
            0, "".join(f"{d}: vendor=0x0000, product=0x0000 ( )\n" for d in state.devices)
        )

    def pam_auth_update(_argv: list[str]) -> Completed:
        if not state.pam_auth_update_works:
            return Completed(0, "Local modifications to /etc/pam.d/common-*, not updating.\n")
        line = "auth\t[success=2 default=ignore]\tpam_u2f.so authfile=/etc/fido2-ble-bridge/"
        line += f"u2f_mappings origin={ORIGIN} cue userverification=1\n"
        paths.common_auth.write_text(line + paths.common_auth.read_text())
        return ok

    runner.on("systemctl", "is-enabled", "--quiet", "fido2-ble-bridge", result=is_enabled)
    runner.on("systemctl", "is-active", "--quiet", "fido2-ble-bridge", result=is_active)
    runner.on("systemctl", "enable", "--now", "fido2-ble-bridge", result=enable_now)
    runner.on("systemctl", "restart", "fido2-ble-bridge", result=enable_now)
    runner.on("systemctl", "stop", "fido2-ble-bridge", result=stop)
    runner.on("systemctl", "start", "fido2-ble-bridge", result=start)
    runner.on("fido2-token", "-I", result=Completed(0, token_info()))
    runner.on("fido2-token", "-L", result=fido_devices)
    runner.on("pamu2fcfg", result=Completed(0, MAPPING))
    runner.on("pam-auth-update", "--enable", "fido2-ble-bridge", result=pam_auth_update)
    return runner
