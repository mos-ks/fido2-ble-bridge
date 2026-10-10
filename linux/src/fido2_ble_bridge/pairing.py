"""Pair a BLE FIDO key with BlueZ over D-Bus, for `fido2-ble-bridge setup`.

Kept apart from bluez.py so the sandboxed daemon never loads pairing code. BlueZ sends any
passkey question to the agent registered by the same D-Bus connection that calls
Device1.Pair(), so the agent is exported and Pair() is called on one connection, and the
desktop's own agent is left alone. The agent answers only for the device being paired.
"""

# No `from __future__ import annotations` here: dbus-fast reads the D-Bus signatures from the
# agent's method annotations when the class is created, and string annotations break that.

import asyncio
import contextlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, Self, TypeVar

from dbus_fast import BusType, Message, MessageType, Variant
from dbus_fast.aio import MessageBus
from dbus_fast.annotations import DBusObjectPath, DBusStr, DBusUInt16, DBusUInt32
from dbus_fast.errors import DBusError
from dbus_fast.service import ServiceInterface, dbus_method

from .ble_link import FIDO_SERVICE_UUID
from .console import Console, confirm

BLUEZ = "org.bluez"
ADAPTER = "org.bluez.Adapter1"
DEVICE = "org.bluez.Device1"
AGENT_MANAGER = "org.bluez.AgentManager1"
PROPERTIES = "org.freedesktop.DBus.Properties"
OBJECT_MANAGER = "org.freedesktop.DBus.ObjectManager"
AGENT_PATH = "/org/fido2_ble_bridge/setup_agent"
# Passkey Entry and Numeric Comparison need a keyboard and a display; BlueZ still pairs a key
# without either with Just Works, which it accepts by itself for a pairing we started.
AGENT_CAPABILITY = "KeyboardDisplay"

REJECTED = "org.bluez.Error.Rejected"
CANCELED = "org.bluez.Error.Canceled"
ALREADY_EXISTS = "org.bluez.Error.AlreadyExists"
BLOCKED = "org.bluez.Error.Blocked"
SERVICE_UNKNOWN = "org.freedesktop.DBus.Error.ServiceUnknown"
TIMED_OUT = "org.fido2_ble_bridge.Error.Timeout"  # ours: BlueZ did not answer in time


class BluetoothError(Exception):
    def __init__(self, name: str, text: str) -> None:
        super().__init__(f"{text} ({name})" if name else text)
        self.name = name
        self.text = text


_PAIR_ADVICE = {
    "org.bluez.Error.AuthenticationFailed": (
        "the key refused the pairing. Put it back in pairing mode and run setup again; if it "
        "asked for a passkey, check the digits."
    ),
    "org.bluez.Error.AuthenticationRejected": (
        "the key rejected the pairing. Put it back in pairing mode and run setup again."
    ),
    "org.bluez.Error.AuthenticationCanceled": (
        "the pairing was cancelled: the key left pairing mode, or no passkey was entered. Put "
        "it back in pairing mode and run setup again."
    ),
    "org.bluez.Error.AuthenticationTimeout": (
        "the key did not finish pairing in time. Keep it close and in pairing mode, then run "
        "setup again."
    ),
    TIMED_OUT: (
        "the key did not finish pairing in time. Keep it close and in pairing mode, then run "
        "setup again."
    ),
    "org.bluez.Error.ConnectionAttemptFailed": (
        "could not connect to the key. Keep it close and in pairing mode, make sure it is not "
        "connected to another device, then run setup again."
    ),
    "org.bluez.Error.InProgress": (
        "another pairing or connection to this key is in progress. Close the desktop's "
        "Bluetooth settings, then run setup again."
    ),
}


def pairing_advice(error: BluetoothError) -> str:
    """What went wrong with Device1.Pair() and what the user can do about it."""
    return _PAIR_ADVICE.get(error.name, f"pairing failed: {error}.")


@dataclass(frozen=True)
class BtDevice:
    path: str
    address: str
    name: str | None
    paired: bool
    bonded: bool
    trusted: bool
    fido: bool
    """Offers the FIDO service (in its advertised or resolved service UUIDs)."""
    advertising: bool
    """Seen during the current discovery (BlueZ reports an RSSI only then)."""

    @property
    def has_bond(self) -> bool:
        return self.paired and self.bonded


def _device(path: str, props: dict[str, Any]) -> BtDevice:
    uuids = {str(uuid).lower() for uuid in props.get("UUIDs", [])}
    uuids |= {str(uuid).lower() for uuid in props.get("ServiceData", {})}
    return BtDevice(
        path=path,
        address=str(props.get("Address", "")).upper(),
        name=props.get("Name"),
        paired=bool(props.get("Paired")),
        bonded=bool(props.get("Bonded")),
        trusted=bool(props.get("Trusted")),
        fido=FIDO_SERVICE_UUID in uuids,
        advertising="RSSI" in props,
    )


class AgentRefusal(Exception):
    def __init__(self, name: str, text: str) -> None:
        super().__init__(text)
        self.name = name


class PairingAgent:
    """The answers of setup's BlueZ agent, as plain methods tests can call directly."""

    def __init__(self, console: Console, device_path: str) -> None:
        self.console = console
        self.device_path = device_path
        self._shown_passkey: int | None = None

    def _only_ours(self, device: str) -> None:
        if device != self.device_path:
            raise AgentRefusal(REJECTED, "setup only answers for the key it is pairing")

    def request_passkey(self, device: str) -> int:
        self._only_ours(device)
        answer = self.console.ask(
            "  The key asks for a passkey. Type the 6 digits from its label or manual: "
        ).strip()
        if not (answer.isdigit() and len(answer) <= 6):
            raise AgentRefusal(CANCELED, "no passkey entered")
        return int(answer)

    def display_passkey(self, device: str, passkey: int, entered: int) -> None:
        self._only_ours(device)
        # BlueZ repeats this call as digits are typed on the key; show the passkey once.
        if passkey != self._shown_passkey:
            self._shown_passkey = passkey
            self.console.say(f"  Type this passkey on the key: {passkey:06d}")

    def request_confirmation(self, device: str, passkey: int) -> None:
        self._only_ours(device)
        if not confirm(
            self.console, f"  Does the key show the passkey {passkey:06d}?", default=False
        ):
            raise AgentRefusal(REJECTED, "passkey not confirmed")

    def request_authorization(self, device: str) -> None:
        # Asked for pairing the device starts itself; BlueZ accepts ours without asking.
        self._only_ours(device)


_T = TypeVar("_T")


def _answer(call: Callable[[], _T]) -> _T:
    try:
        return call()
    except AgentRefusal as refusal:
        raise DBusError(refusal.name, str(refusal)) from refusal


class AgentInterface(ServiceInterface):
    """org.bluez.Agent1, a thin delegate: dbus-fast drops what a decorated method returns when
    Python code calls it, so the answers live in PairingAgent."""

    def __init__(self, agent: PairingAgent) -> None:
        super().__init__("org.bluez.Agent1")
        self.agent = agent

    @dbus_method()
    def Release(self) -> None:
        pass

    @dbus_method()
    def RequestPinCode(self, device: DBusObjectPath) -> DBusStr:
        raise DBusError(REJECTED, "PIN codes are for classic Bluetooth only")

    @dbus_method()
    def DisplayPinCode(self, device: DBusObjectPath, pincode: DBusStr) -> None:
        raise DBusError(REJECTED, "PIN codes are for classic Bluetooth only")

    @dbus_method()
    def RequestPasskey(self, device: DBusObjectPath) -> DBusUInt32:
        return _answer(lambda: self.agent.request_passkey(device))

    @dbus_method()
    def DisplayPasskey(
        self, device: DBusObjectPath, passkey: DBusUInt32, entered: DBusUInt16
    ) -> None:
        _answer(lambda: self.agent.display_passkey(device, passkey, entered))

    @dbus_method()
    def RequestConfirmation(self, device: DBusObjectPath, passkey: DBusUInt32) -> None:
        _answer(lambda: self.agent.request_confirmation(device, passkey))

    @dbus_method()
    def RequestAuthorization(self, device: DBusObjectPath) -> None:
        _answer(lambda: self.agent.request_authorization(device))

    @dbus_method()
    def AuthorizeService(self, device: DBusObjectPath, uuid: DBusStr) -> None:
        raise DBusError(REJECTED, "setup does not authorize services")

    @dbus_method()
    def Cancel(self) -> None:
        pass


class Bus(Protocol):
    """The part of dbus-fast's MessageBus used here; tests pass an in-process fake BlueZ."""

    async def call(self, msg: Message) -> Message | None: ...
    def export(self, path: str, interface: ServiceInterface) -> None: ...
    def unexport(self, path: str, interface: ServiceInterface | str | None = None) -> None: ...
    def disconnect(self) -> None: ...


async def connect_system_bus() -> Bus:
    try:
        return await MessageBus(bus_type=BusType.SYSTEM).connect()
    except Exception as exc:
        raise BluetoothError("", f"cannot connect to the system D-Bus: {exc}") from exc


class BluezPairing:
    """One D-Bus connection to BlueZ for one adapter: discovery, pairing, trust and removal."""

    def __init__(self, bus: Bus, adapter_path: str, *, call_timeout: float = 30.0) -> None:
        self._bus = bus
        self.adapter_path = adapter_path
        self.adapter_count = 1
        """How many adapters BlueZ has; with more than one, the choice must be written down."""
        self._call_timeout = call_timeout

    @property
    def adapter(self) -> str:
        """The adapter's name, hciN."""
        return self.adapter_path.rsplit("/", 1)[-1]

    @classmethod
    async def open(cls, bus: Bus, adapter: str | None, *, key: str | None = None) -> Self:
        """Use `adapter` (hciN); or else the first adapter with a bond with `key` (an address),
        the first powered one, or the first one."""
        pairing = cls(bus, "")
        objects = await pairing._objects()
        adapters = sorted(path for path, interfaces in objects.items() if ADAPTER in interfaces)
        wanted = f"/org/bluez/{adapter}" if adapter else None
        if wanted is not None and wanted not in adapters:
            raise BluetoothError("", f"BlueZ has no adapter {adapter}")
        if not adapters:
            raise BluetoothError("", "no Bluetooth adapter found")
        bonds = [
            device
            for path, interfaces in objects.items()
            if DEVICE in interfaces and (device := _device(path, interfaces[DEVICE])).has_bond
        ]
        holding = [
            path
            for path in adapters
            if any(device.address == key and device.path.startswith(path + "/") for device in bonds)
        ]
        powered = [path for path in adapters if objects[path][ADAPTER].get("Powered")]
        pairing.adapter_path = wanted or (holding or powered or adapters)[0]
        pairing.adapter_count = len(adapters)
        return pairing

    def close(self) -> None:
        self._bus.disconnect()

    async def _call(
        self,
        path: str,
        interface: str,
        member: str,
        signature: str = "",
        body: list[Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> list[Any]:
        message = Message(
            destination=BLUEZ,
            path=path,
            interface=interface,
            member=member,
            signature=signature,
            body=body or [],
        )
        limit = self._call_timeout if timeout is None else timeout
        try:
            async with asyncio.timeout(limit):
                reply = await self._bus.call(message)
        except TimeoutError as exc:
            raise BluetoothError(TIMED_OUT, f"BlueZ did not answer {member} in {limit:g}s") from exc
        if reply is None:
            raise BluetoothError("", f"no reply to {member}")
        if reply.message_type == MessageType.ERROR:
            text = str(reply.body[0]) if reply.body else member
            if reply.error_name == SERVICE_UNKNOWN:
                text = "BlueZ is not running; start it with sudo systemctl enable --now bluetooth"
            raise BluetoothError(reply.error_name or "", text)
        return list(reply.body)

    async def _objects(self) -> dict[str, dict[str, dict[str, Any]]]:
        (objects,) = await self._call("/", OBJECT_MANAGER, "GetManagedObjects")
        return {
            path: {
                interface: {name: variant.value for name, variant in props.items()}
                for interface, props in interfaces.items()
            }
            for path, interfaces in objects.items()
        }

    async def _set(self, path: str, interface: str, name: str, value: Variant) -> None:
        await self._call(path, PROPERTIES, "Set", "ssv", [interface, name, value])

    async def devices(self) -> list[BtDevice]:
        prefix = self.adapter_path + "/"
        return [
            _device(path, interfaces[DEVICE])
            for path, interfaces in sorted((await self._objects()).items())
            if path.startswith(prefix) and DEVICE in interfaces
        ]

    async def device(self, path: str) -> BtDevice | None:
        return next((device for device in await self.devices() if device.path == path), None)

    async def _adapter_flag(self, name: str) -> bool:
        (props,) = await self._call(self.adapter_path, PROPERTIES, "GetAll", "s", [ADAPTER])
        variant = props.get(name)
        return variant is not None and bool(variant.value)

    async def power_on(self) -> bool:
        """Turn the adapter on if it is off; True if it was off."""
        if await self._adapter_flag("Powered"):
            return False
        await self._set(self.adapter_path, ADAPTER, "Powered", Variant("b", True))
        return True

    async def make_pairable(self) -> bool:
        """Without Pairable the kernel pairs without storing a bond; True if it was off."""
        if await self._adapter_flag("Pairable"):
            return False
        await self._set(self.adapter_path, ADAPTER, "Pairable", Variant("b", True))
        return True

    async def start_discovery(self) -> None:
        await self._call(
            self.adapter_path,
            ADAPTER,
            "SetDiscoveryFilter",
            "a{sv}",
            [{"Transport": Variant("s", "le"), "UUIDs": Variant("as", [FIDO_SERVICE_UUID])}],
        )
        await self._call(self.adapter_path, ADAPTER, "StartDiscovery")

    async def stop_discovery(self) -> None:
        with contextlib.suppress(BluetoothError):
            await self._call(self.adapter_path, ADAPTER, "StopDiscovery")

    async def pair(self, path: str, agent: PairingAgent, *, timeout: float) -> None:
        interface = AgentInterface(agent)
        self._bus.export(AGENT_PATH, interface)
        try:
            await self._call(
                "/org/bluez", AGENT_MANAGER, "RegisterAgent", "os", [AGENT_PATH, AGENT_CAPABILITY]
            )
            try:
                await self._call(path, DEVICE, "Pair", timeout=timeout)
            except BluetoothError as exc:
                if exc.name == TIMED_OUT:
                    with contextlib.suppress(BluetoothError):
                        await self._call(path, DEVICE, "CancelPairing")
                raise
        finally:
            with contextlib.suppress(BluetoothError):
                await self._call("/org/bluez", AGENT_MANAGER, "UnregisterAgent", "o", [AGENT_PATH])
            self._bus.unexport(AGENT_PATH, interface)

    async def trust(self, path: str) -> None:
        await self._set(path, DEVICE, "Trusted", Variant("b", True))

    async def disconnect(self, path: str) -> None:
        # A connected key does not advertise, and the bridge finds the key by its advertising.
        with contextlib.suppress(BluetoothError):
            await self._call(path, DEVICE, "Disconnect")

    async def remove(self, path: str) -> None:
        await self._call(self.adapter_path, ADAPTER, "RemoveDevice", "o", [path])
