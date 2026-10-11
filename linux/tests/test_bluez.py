import asyncio
import contextlib
from typing import Any

import pytest
from bleak import BleakScanner
from bleak.args.bluez import BlueZScannerArgs
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from bleak.exc import BleakDBusError, BleakDeviceNotFoundError, BleakError
from dbus_fast import Variant

from fido2_ble_bridge import bluez
from fido2_ble_bridge.ble_link import FIDO_SERVICE_UUID, KeyNotReachable
from fido2_ble_bridge.bluez import (
    FoundKey,
    connect_with_retry,
    device_path_for,
    raise_if_adapter_stuck,
    scan_fido_devices,
)


def test_device_path_is_found_by_address_and_adapter() -> None:
    objects: dict[str, dict[str, dict[str, Any]]] = {
        "/org/bluez/hci0": {"org.bluez.Adapter1": {}},
        "/org/bluez/hci0/dev_AA_BB": {"org.bluez.Device1": {"Address": Variant("s", "aa:bb")}},
        "/org/bluez/hci1/dev_AA_BB": {"org.bluez.Device1": {"Address": Variant("s", "AA:BB")}},
        "/org/bluez/hci1/dev_CC_DD": {"org.bluez.Device1": {"Address": Variant("s", "CC:DD")}},
    }
    assert device_path_for(objects, "AA:BB", None) == "/org/bluez/hci0/dev_AA_BB"
    assert device_path_for(objects, "AA:BB", "hci1") == "/org/bluez/hci1/dev_AA_BB"
    assert device_path_for(objects, "EE:FF", None) is None
    assert device_path_for(objects, "CC:DD", "hci0") is None


class _Client:
    def __init__(self, errors: list[str | Exception], log: list[float], timeout: float) -> None:
        self._errors = errors
        log.append(timeout)

    async def connect(self) -> None:
        if self._errors:
            error = self._errors.pop(0)
            raise error if isinstance(error, Exception) else BleakDBusError(error, ["busy"])


async def test_connect_retries_errors_that_clear_up_by_themselves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bluez, "CONNECT_RETRY_DELAY", 0.01)
    errors = ["org.bluez.Error.InProgress", "org.bluez.Error.Failed"]
    attempts: list[float] = []
    client = await connect_with_retry(lambda t: _Client(errors, attempts, t), 5)  # type: ignore[arg-type,return-value]
    assert isinstance(client, _Client)
    assert len(attempts) == 3
    assert all(0 < t <= 5 for t in attempts)


async def test_connect_gives_up_at_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bluez, "CONNECT_RETRY_DELAY", 0.05)
    errors = ["org.bluez.Error.InProgress"] * 1000
    with pytest.raises(KeyNotReachable, match="InProgress"):
        await connect_with_retry(lambda t: _Client(errors, [], t), 0.2)  # type: ignore[arg-type,return-value]


class _Scanner:
    """Fake BleakScanner: start() may be refused; once started, `address` advertises after
    `advertise_after` seconds (never if None)."""

    def __init__(self, callback: Any, script: dict[str, Any]) -> None:
        self._callback = callback
        self._script = script
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._script["starts"] += 1
        if self._script["refusals"]:
            self._script["refusals"] -= 1
            raise BleakDBusError("org.bluez.Error.InProgress", ["Operation already in progress"])
        self._script["running"] += 1
        delay = self._script["advertise_after"]
        if delay is not None:
            self._task = asyncio.create_task(self._advertise(delay))

    async def _advertise(self, delay: float) -> None:
        await asyncio.sleep(delay)
        self._callback(BLEDevice(self._script["address"].lower(), None, {}), None)

    async def stop(self) -> None:
        await asyncio.sleep(0.01)
        self._script["running"] -= 1
        if self._task is not None:
            self._task.cancel()


def _script(**overrides: Any) -> dict[str, Any]:
    script = {"address": "AA:BB", "refusals": 0, "advertise_after": 0.01, "starts": 0, "running": 0}
    script.update(overrides)
    return script


async def test_a_refused_scan_after_a_failed_connect_names_the_adapter() -> None:
    script = _script(refusals=1)
    with pytest.raises(KeyNotReachable, match="bluetoothctl power off") as raised:
        await raise_if_adapter_stuck(lambda cb: _Scanner(cb, script))  # type: ignore[arg-type,return-value]
    assert "org.bluez.Error.InProgress" in str(raised.value)
    assert script["running"] == 0


async def test_a_scan_that_starts_is_stopped_and_blames_nothing() -> None:
    script = _script(advertise_after=None)
    await raise_if_adapter_stuck(lambda cb: _Scanner(cb, script))  # type: ignore[arg-type,return-value]
    assert script["starts"] == 1
    assert script["running"] == 0


async def test_the_check_scan_is_stopped_even_when_the_caller_is_cancelled() -> None:
    script = _script(advertise_after=None)
    checker = asyncio.create_task(raise_if_adapter_stuck(lambda cb: _Scanner(cb, script)))  # type: ignore[arg-type,return-value]
    await asyncio.sleep(0.005)  # inside the shielded stop
    checker.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await checker
    await asyncio.sleep(0.05)
    assert script["running"] == 0


async def test_a_link_dropped_while_connecting_is_connected_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bluez, "CONNECT_RETRY_DELAY", 0.01)
    errors: list[str | Exception] = [BleakError("failed to discover services, device disconnected")]
    attempts: list[float] = []
    client = await connect_with_retry(lambda t: _Client(errors, attempts, t), 5)  # type: ignore[arg-type,return-value]
    assert isinstance(client, _Client)
    assert len(attempts) == 2


async def test_a_device_bluez_does_not_know_is_not_retried() -> None:
    errors: list[str | Exception] = [BleakDeviceNotFoundError("AA:BB")]
    attempts: list[float] = []
    with pytest.raises(BleakDeviceNotFoundError):
        await connect_with_retry(lambda t: _Client(errors, attempts, t), 5)  # type: ignore[arg-type,return-value]
    assert len(attempts) == 1


async def test_connect_does_not_retry_other_errors() -> None:
    errors = ["org.bluez.Error.AuthenticationFailed"]
    attempts: list[float] = []
    with pytest.raises(BleakDBusError):
        await connect_with_retry(lambda t: _Client(errors, attempts, t), 5)  # type: ignore[arg-type,return-value]
    assert len(attempts) == 1


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
