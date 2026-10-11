"""BlueZ (via bleak) implementation of the GATT protocols in ble_link.

Every connection is gated on BlueZ reporting the configured address as paired and bonded. For a
device with an LE bond BlueZ raises the link to encryption with the stored LTK as it connects,
so a device that spoofs the address without that key cannot complete the connection.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, NamedTuple

from bleak import BleakClient, BleakScanner
from bleak.args.bluez import BlueZClientArgs, BlueZScannerArgs
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.backends.service import BleakGATTService
from bleak.exc import BleakDBusError
from dbus_fast import BusType, Message, MessageType
from dbus_fast.aio import MessageBus

from .ble_link import (
    CONTROL_POINT_LENGTH_UUID,
    CONTROL_POINT_UUID,
    FIDO_SERVICE_UUID,
    SERVICE_REVISION_BITFIELD_UUID,
    STATUS_UUID,
    GattSession,
    KeyNotReachable,
    KeyNotTrusted,
    KeyUnsupported,
)

log = logging.getLogger(__name__)

BLUEZ_SERVICE = "org.bluez"
DEVICE_INTERFACE = "org.bluez.Device1"
LE_BEARER_INTERFACE = "org.bluez.Bearer.LE1"


@dataclass(frozen=True)
class BondState:
    device: dict[str, Any]
    le_bearer: dict[str, Any] | None
    """org.bluez.Bearer.LE1 properties; only newer BlueZ (2025+, experimental) exposes them."""


def _paired_and_bonded(props: Mapping[str, Any]) -> bool:
    return bool(props.get("Paired")) and bool(props.get("Bonded"))


def check_bond(state: BondState, address: str) -> None:
    """Refuse anything that is not the configured device with a stored LE bond.

    Device1.Paired/Bonded also count a BR/EDR-only bond, and BlueZ only forces encryption on LE
    connections when the bond is an LE one. Where BlueZ reports the LE bearer separately, that
    is checked too; otherwise the device-level flags are all there is to go on.
    """
    props = state.device
    if str(props.get("Address", "")).upper() != address:
        raise KeyNotTrusted(f"BlueZ device reports address {props.get('Address')!r}")
    if not _paired_and_bonded(props):
        raise KeyNotTrusted(
            f"{address} is not bonded with this host; pair and trust it with bluetoothctl"
        )
    le = state.le_bearer
    if le is not None and not _paired_and_bonded(le):
        raise KeyNotTrusted(f"{address} is bonded over classic Bluetooth only, not over LE")


async def _get_all(bus: MessageBus, path: str, interface: str) -> dict[str, Any] | None:
    reply = await bus.call(
        Message(
            destination=BLUEZ_SERVICE,
            path=path,
            interface="org.freedesktop.DBus.Properties",
            member="GetAll",
            signature="s",
            body=[interface],
        )
    )
    if reply is None or reply.message_type == MessageType.ERROR:
        return None
    return {name: variant.value for name, variant in reply.body[0].items()}


async def read_bond_state(device_path: str) -> BondState:
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    try:
        device = await _get_all(bus, device_path, DEVICE_INTERFACE)
        le_bearer = await _get_all(bus, device_path, LE_BEARER_INTERFACE)
    finally:
        bus.disconnect()
    if device is None:
        raise KeyNotTrusted(f"BlueZ has no device object at {device_path}")
    return BondState(device, le_bearer)


def _required(service: BleakGATTService, uuid: str) -> BleakGATTCharacteristic:
    characteristic = service.get_characteristic(uuid)
    if characteristic is None:
        raise KeyUnsupported(f"FIDO service lacks characteristic {uuid}")
    return characteristic


class BleakGattSession:
    def __init__(self, client: BleakClient) -> None:
        self._client = client
        service = client.services.get_service(FIDO_SERVICE_UUID)
        if service is None:
            raise KeyUnsupported("device does not expose the FIDO GATT service")
        self._control_point = _required(service, CONTROL_POINT_UUID)
        self._status = _required(service, STATUS_UUID)
        self._control_point_length = _required(service, CONTROL_POINT_LENGTH_UUID)
        self._revision_bitfield = service.get_characteristic(SERVICE_REVISION_BITFIELD_UUID)

    async def read_revision_bitfield(self) -> bytes | None:
        if self._revision_bitfield is None:
            return None
        return bytes(await self._client.read_gatt_char(self._revision_bitfield))

    async def write_revision_bitfield(self, value: bytes) -> None:
        if self._revision_bitfield is None:
            raise KeyUnsupported("FIDO service has no fidoServiceRevisionBitfield")
        await self._client.write_gatt_char(self._revision_bitfield, value, response=True)

    async def read_control_point_length(self) -> bytes:
        return bytes(await self._client.read_gatt_char(self._control_point_length))

    async def write_control_point(self, fragment: bytes) -> None:
        await self._client.write_gatt_char(self._control_point, fragment, response=True)

    async def start_status_notifications(self, callback: Callable[[bytes], None]) -> None:
        await self._client.start_notify(
            self._status, lambda _characteristic, data: callback(bytes(data))
        )

    async def disconnect(self) -> None:
        await self._client.disconnect()


def device_path_for(
    objects: Mapping[str, Mapping[str, Mapping[str, Any]]], address: str, adapter: str | None
) -> str | None:
    """The BlueZ object path of the device with `address` (on `adapter`, if given) in the result
    of ObjectManager.GetManagedObjects, or None if BlueZ doesn't know it."""
    prefix = f"/org/bluez/{adapter}/" if adapter else "/org/bluez/"
    for path, interfaces in objects.items():
        props = interfaces.get(DEVICE_INTERFACE)
        if props is None or not path.startswith(prefix):
            continue
        found = props.get("Address")
        if str(getattr(found, "value", found)).upper() == address:
            return path
    return None


async def find_device_path(address: str, adapter: str | None) -> str | None:
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    try:
        reply = await bus.call(
            Message(
                destination=BLUEZ_SERVICE,
                path="/",
                interface="org.freedesktop.DBus.ObjectManager",
                member="GetManagedObjects",
            )
        )
    finally:
        bus.disconnect()
    if reply is None or reply.message_type == MessageType.ERROR:
        return None
    return device_path_for(reply.body[0], address, adapter)


# Connect errors that clear up by themselves within a connect window: InProgress while another
# connect, or the service discovery after one, is still running (BlueZ's own or another program's);
# Failed for an LE connection attempt that ended because the key wasn't advertising yet.
RETRYABLE_CONNECT_ERRORS = frozenset({"org.bluez.Error.InProgress", "org.bluez.Error.Failed"})
CONNECT_RETRY_DELAY = 0.5


async def connect_with_retry(
    make_client: Callable[[float], BleakClient], timeout: float
) -> BleakClient:
    """Connects a fresh client per attempt, retrying RETRYABLE_CONNECT_ERRORS until `timeout`."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        client = make_client(max(1.0, deadline - loop.time()))
        try:
            await client.connect()
            return client
        except BleakDBusError as exc:
            if exc.dbus_error not in RETRYABLE_CONNECT_ERRORS:
                raise
            if loop.time() + CONNECT_RETRY_DELAY >= deadline:
                raise KeyNotReachable(f"connecting to the authenticator failed: {exc}") from exc
            log.debug("BlueZ refused the connect (%s), retrying", exc.dbus_error)
            await asyncio.sleep(CONNECT_RETRY_DELAY)


SCAN_RETRY_DELAY = 0.5


async def wait_for_advertisement(
    make_scanner: Callable[[Callable[[BLEDevice, Any], None]], BleakScanner],
    address: str,
    timeout: float,
) -> None:
    """Scans until `address` advertises (a sleeping key does once it is woken), within `timeout`.

    BlueZ refuses a new scan from a client whose earlier scan is still running (InProgress), so
    the scan is always stopped, even when the caller is cancelled, and a refused start is retried.
    BlueZ also answers InProgress whenever the kernel refuses to start discovery, which a stuck
    controller does on every attempt until it is reset; the final error says so.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    seen = asyncio.Event()

    def on_advertisement(device: BLEDevice, _advertisement: Any) -> None:
        if device.address.upper() == address:
            seen.set()

    while True:
        scanner = make_scanner(on_advertisement)
        try:
            await scanner.start()
        except BleakDBusError as exc:
            if exc.dbus_error != "org.bluez.Error.InProgress":
                raise
            if loop.time() + SCAN_RETRY_DELAY >= deadline:
                raise KeyNotReachable(
                    f"BlueZ kept refusing to scan for the authenticator ({exc.dbus_error}); the "
                    "Bluetooth adapter is probably stuck: turn it off and on with "
                    "`bluetoothctl power off` and `bluetoothctl power on`"
                ) from exc
            log.debug("BlueZ refused the scan (%s), retrying", exc.dbus_error)
            await asyncio.sleep(SCAN_RETRY_DELAY)
            continue
        try:
            async with asyncio.timeout(max(0.0, deadline - loop.time())):
                await seen.wait()
            return
        except TimeoutError as exc:
            raise KeyNotReachable(f"{address} did not advertise within {timeout:g}s") from exc
        finally:
            # Shielded: a scan left running makes BlueZ refuse this client's next one.
            with contextlib.suppress(Exception):
                await asyncio.shield(scanner.stop())


class BleakGattConnector:
    """Connects to the bonded key through the device object BlueZ keeps for it.

    A sleeping key is reachable only once it advertises again, so unless BlueZ already has it
    connected, the connector first scans for its advertisement. BlueZ's own LE connect waits for
    it too, through the kernel's background scan, but when the adapter refuses to scan that
    connect just never completes; the explicit scan reports the refusal instead.
    """

    def __init__(self, address: str, adapter: str | None = None) -> None:
        self._address = address.upper()
        self._adapter = adapter
        self._scanner_args = BlueZScannerArgs(adapter=adapter) if adapter else BlueZScannerArgs()
        self._client_args = BlueZClientArgs(adapter=adapter) if adapter else BlueZClientArgs()

    async def connect(self, timeout: float, on_disconnect: Callable[[], None]) -> GattSession:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        device_path = await find_device_path(self._address, self._adapter)
        if device_path is None:
            raise KeyNotTrusted(
                f"{self._address} is not paired with this host; run fido2-ble-bridge setup"
            )
        state = await read_bond_state(device_path)
        check_bond(state, self._address)
        if not state.device.get("Connected"):
            # A connected key doesn't advertise, so only scan when BlueZ has no link to it.
            await wait_for_advertisement(
                lambda callback: BleakScanner(callback, bluez=self._scanner_args),
                self._address,
                max(0.0, deadline - loop.time()),
            )
        device = BLEDevice(self._address, None, {"path": device_path, "props": state.device})

        client = await connect_with_retry(
            lambda remaining: BleakClient(
                device,
                disconnected_callback=lambda _client: on_disconnect(),
                services=[FIDO_SERVICE_UUID],
                timeout=remaining,
                bluez=self._client_args,
            ),
            max(0.0, deadline - loop.time()),
        )
        try:
            # Re-read after connecting: pairing state can change between scan and connect.
            check_bond(await read_bond_state(device_path), self._address)
            return BleakGattSession(client)
        except BaseException:
            with contextlib.suppress(Exception):
                async with asyncio.timeout(5):
                    await client.disconnect()
            raise


class FoundKey(NamedTuple):
    """A device advertising the FIDO service.

    `bonded` reflects the device-level Paired and Bonded flags only. check_bond, which gates
    every connection, also requires the LE bond where BlueZ reports it. `path` is the BlueZ
    object path of the device.
    """

    address: str
    name: str | None
    bonded: bool
    path: str


async def scan_fido_devices(timeout: float, adapter: str | None = None) -> list[FoundKey]:
    """Nearby devices advertising the FIDO service, sorted by address."""
    found = await BleakScanner.discover(
        timeout=timeout,
        return_adv=True,
        service_uuids=[FIDO_SERVICE_UUID],
        bluez=BlueZScannerArgs(adapter=adapter) if adapter else BlueZScannerArgs(),
    )
    keys = []
    for device, adv in found.values():
        details = device.details if isinstance(device.details, dict) else {}
        keys.append(
            FoundKey(
                address=device.address,
                name=adv.local_name or device.name,
                bonded=_paired_and_bonded(details.get("props", {})),
                path=str(details.get("path", "")),
            )
        )
    return sorted(keys, key=lambda key: key.address)
