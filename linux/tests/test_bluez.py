from typing import Any

import pytest
from bleak import BleakScanner
from bleak.args.bluez import BlueZScannerArgs
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from fido2_ble_bridge.ble_link import FIDO_SERVICE_UUID
from fido2_ble_bridge.bluez import FoundKey, scan_fido_devices


def advertised(
    address: str, *, name: str | None, local_name: str | None, props: dict[str, Any]
) -> tuple[BLEDevice, AdvertisementData]:
    path = "/org/bluez/hci1/dev_" + address.replace(":", "_")
    device = BLEDevice(address, name, {"path": path, "props": props})
    advertisement = AdvertisementData(
        local_name=local_name,
        manufacturer_data={},
        service_data={},
        service_uuids=[FIDO_SERVICE_UUID],
        tx_power=None,
        rssi=-60,
        platform_data=(),
    )
    return device, advertisement


async def test_scan_reports_fido_devices_by_address_with_their_bond_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    found = {
        "BB:00:00:00:00:02": advertised(
            "BB:00:00:00:00:02",
            name="BlueZ name",
            local_name=None,
            props={"Paired": True, "Bonded": False},
        ),
        "AA:00:00:00:00:01": advertised(
            "AA:00:00:00:00:01",
            name="BlueZ name",
            local_name="Advertised name",
            props={"Paired": True, "Bonded": True},
        ),
    }
    calls: list[dict[str, Any]] = []

    async def discover(**kwargs: Any) -> dict[str, tuple[BLEDevice, AdvertisementData]]:
        calls.append(kwargs)
        return found

    monkeypatch.setattr(BleakScanner, "discover", discover)
    keys = await scan_fido_devices(4.0, "hci1")
    # The device-level flags only; check_bond also looks at the LE bearer before connecting.
    assert [(key.address, key.name, key.bonded) for key in keys] == [
        ("AA:00:00:00:00:01", "Advertised name", True),
        ("BB:00:00:00:00:02", "BlueZ name", False),
    ]
    assert keys[0] == FoundKey(
        "AA:00:00:00:00:01", "Advertised name", True, "/org/bluez/hci1/dev_AA_00_00_00_00_01"
    )
    assert calls == [
        {
            "timeout": 4.0,
            "return_adv": True,
            "service_uuids": [FIDO_SERVICE_UUID],
            "bluez": BlueZScannerArgs(adapter="hci1"),
        }
    ]
