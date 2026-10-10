"""BlueZ (via bleak) implementation of the GATT protocols in ble_link.

Every connection is gated on BlueZ reporting the configured address as paired and bonded. For a
bonded device BlueZ raises the link to encryption with the stored LTK as it connects, so a
device that spoofs the address without the key cannot complete the connection.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from typing import Any

from bleak import BleakClient, BleakScanner
from bleak.args.bluez import BlueZClientArgs, BlueZScannerArgs
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.service import BleakGATTService
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


def check_bond(props: dict[str, Any], address: str) -> None:
    """Refuse anything that is not the configured, bonded device."""
    if str(props.get("Address", "")).upper() != address:
        raise KeyNotTrusted(f"BlueZ device reports address {props.get('Address')!r}")
    if not props.get("Paired") or not props.get("Bonded"):
        raise KeyNotTrusted(
            f"{address} is not bonded with this host; pair and trust it with bluetoothctl"
        )


async def read_device_properties(device_path: str) -> dict[str, Any]:
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    try:
        reply = await bus.call(
            Message(
                destination=BLUEZ_SERVICE,
                path=device_path,
                interface="org.freedesktop.DBus.Properties",
                member="GetAll",
                signature="s",
                body=[DEVICE_INTERFACE],
            )
        )
    finally:
        bus.disconnect()
    if reply is None or reply.message_type == MessageType.ERROR:
        raise KeyNotTrusted(f"BlueZ has no device object at {device_path}")
    return {name: variant.value for name, variant in reply.body[0].items()}


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

    @property
    def fragment_limit(self) -> int:
        return self._control_point.max_write_without_response_size

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


class BleakGattConnector:
    def __init__(self, address: str, adapter: str | None = None) -> None:
        self._address = address.upper()
        self._scanner_args = BlueZScannerArgs(adapter=adapter) if adapter else BlueZScannerArgs()
        self._client_args = BlueZClientArgs(adapter=adapter) if adapter else BlueZClientArgs()

    async def connect(self, timeout: float, on_disconnect: Callable[[], None]) -> GattSession:
        device = await BleakScanner.find_device_by_filter(
            lambda found, _adv: found.address.upper() == self._address,
            timeout=timeout,
            bluez=self._scanner_args,
        )
        if device is None:
            raise KeyNotReachable(f"{self._address} did not advertise within {timeout:g}s")
        device_path = device.details["path"]
        check_bond(await read_device_properties(device_path), self._address)

        client = BleakClient(
            device,
            disconnected_callback=lambda _client: on_disconnect(),
            services=[FIDO_SERVICE_UUID],
            timeout=timeout,
            bluez=self._client_args,
        )
        await client.connect()
        try:
            # Re-read after connecting: pairing state can change between scan and connect.
            check_bond(await read_device_properties(device_path), self._address)
            return BleakGattSession(client)
        except BaseException:
            with contextlib.suppress(Exception):
                async with asyncio.timeout(5):
                    await client.disconnect()
            raise


async def scan_fido_devices(
    timeout: float, adapter: str | None = None
) -> list[tuple[str, str | None, bool]]:
    """Addresses, names and bond state of nearby devices advertising the FIDO service."""
    found = await BleakScanner.discover(
        timeout=timeout,
        return_adv=True,
        service_uuids=[FIDO_SERVICE_UUID],
        bluez=BlueZScannerArgs(adapter=adapter) if adapter else BlueZScannerArgs(),
    )
    results = []
    for device, adv in found.values():
        props = device.details.get("props", {}) if isinstance(device.details, dict) else {}
        bonded = bool(props.get("Paired")) and bool(props.get("Bonded"))
        results.append((device.address, adv.local_name or device.name, bonded))
    return sorted(results)
