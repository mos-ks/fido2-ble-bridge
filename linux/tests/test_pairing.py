"""setup's BlueZ agent and D-Bus client, against the fake BlueZ in setup_fakes."""

from __future__ import annotations

import asyncio
import inspect
from typing import Any

import pytest
from dbus_fast.errors import DBusError
from setup_fakes import KEY, FakeBluez, ScriptedConsole, device_path

from fido2_ble_bridge.pairing import (
    ADAPTER,
    CANCELED,
    REJECTED,
    TIMED_OUT,
    AgentInterface,
    AgentRefusal,
    BluetoothError,
    BluezPairing,
    PairingAgent,
    pairing_advice,
)

OURS = device_path(KEY)
OTHER = device_path("22:33:44:55:66:77")


def call(interface: AgentInterface, method: str, *args: Any) -> Any:
    """Run a D-Bus method the way dbus-fast does when bluetoothd calls it."""
    return inspect.unwrap(getattr(AgentInterface, method))(interface, *args)


def test_the_agent_matches_bluez_s_agent1_api() -> None:
    methods = AgentInterface(PairingAgent(ScriptedConsole(), OURS)).introspect().methods
    assert {(m.name, m.in_signature, m.out_signature) for m in methods} == {
        ("Release", "", ""),
        ("RequestPinCode", "o", "s"),
        ("DisplayPinCode", "os", ""),
        ("RequestPasskey", "o", "u"),
        ("DisplayPasskey", "ouq", ""),
        ("RequestConfirmation", "ou", ""),
        ("RequestAuthorization", "o", ""),
        ("AuthorizeService", "os", ""),
        ("Cancel", "", ""),
    }


def test_a_typed_passkey_is_returned_to_bluez() -> None:
    console = ScriptedConsole(" 004711 ")
    interface = AgentInterface(PairingAgent(console, OURS))
    assert call(interface, "RequestPasskey", OURS) == 4711
    assert "passkey" in console.prompts[0]


@pytest.mark.parametrize("typed", ["", "12a456", "1234567"])
def test_no_valid_passkey_cancels(typed: str) -> None:
    interface = AgentInterface(PairingAgent(ScriptedConsole(typed), OURS))
    with pytest.raises(DBusError) as raised:
        call(interface, "RequestPasskey", OURS)
    assert raised.value.type == CANCELED


def test_the_agent_answers_only_for_the_key_being_paired() -> None:
    console = ScriptedConsole()
    interface = AgentInterface(PairingAgent(console, OURS))
    for method, args in (
        ("RequestPasskey", (OTHER,)),
        ("RequestConfirmation", (OTHER, 123456)),
        ("RequestAuthorization", (OTHER,)),
        ("DisplayPasskey", (OTHER, 123456, 0)),
    ):
        with pytest.raises(DBusError) as raised:
            call(interface, method, *args)
        assert raised.value.type == REJECTED
    assert console.prompts == []


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("RequestPinCode", (OURS,)),
        ("DisplayPinCode", (OURS, "0000")),
        ("AuthorizeService", (OURS, "0000fffd-0000-1000-8000-00805f9b34fb")),
    ],
)
def test_pin_codes_and_service_authorization_are_refused(method: str, args: tuple[Any]) -> None:
    with pytest.raises(DBusError) as raised:
        call(AgentInterface(PairingAgent(ScriptedConsole(), OURS)), method, *args)
    assert raised.value.type == REJECTED


def test_numeric_comparison_needs_a_yes() -> None:
    agent = PairingAgent(ScriptedConsole("y", ""), OURS)
    agent.request_confirmation(OURS, 42)
    with pytest.raises(AgentRefusal):
        agent.request_confirmation(OURS, 42)


def test_a_displayed_passkey_is_shown_once_while_digits_are_typed() -> None:
    console = ScriptedConsole()
    agent = PairingAgent(console, OURS)
    for entered in range(4):
        agent.display_passkey(OURS, 1234, entered)
    assert console.lines == ["  Type this passkey on the key: 001234"]


async def test_the_named_adapter_or_else_the_first_powered_one_is_used() -> None:
    bluez = FakeBluez()
    assert (await BluezPairing.open(bluez, None)).adapter_count == 1
    bluez.objects["/org/bluez/hci1"] = {ADAPTER: {"Powered": True, "Pairable": True}}
    first = await BluezPairing.open(bluez, None)
    assert (first.adapter, first.adapter_count) == ("hci0", 2)
    assert (await BluezPairing.open(bluez, "hci1")).adapter_path == "/org/bluez/hci1"
    bluez.objects["/org/bluez/hci0"][ADAPTER]["Powered"] = False
    assert (await BluezPairing.open(bluez, None)).adapter == "hci1"
    bluez.objects["/org/bluez/hci1"][ADAPTER]["Powered"] = False
    assert (await BluezPairing.open(bluez, None)).adapter == "hci0"
    with pytest.raises(BluetoothError, match="no adapter hci2"):
        await BluezPairing.open(bluez, "hci2")
    del bluez.objects["/org/bluez/hci0"], bluez.objects["/org/bluez/hci1"]
    with pytest.raises(BluetoothError, match="no Bluetooth adapter"):
        await BluezPairing.open(bluez, None)


async def test_the_adapter_holding_the_key_s_bond_comes_first() -> None:
    # Even switched off: setup turns it on, while another adapter would mean pairing again.
    bluez = FakeBluez(powered=False)
    bluez.objects["/org/bluez/hci1"] = {ADAPTER: {"Powered": True, "Pairable": True}}
    bluez.add_device(KEY, paired=True, bonded=True)  # on hci0
    assert (await BluezPairing.open(bluez, None, key=KEY)).adapter == "hci0"
    assert (await BluezPairing.open(bluez, None, key="22:33:44:55:66:77")).adapter == "hci1"
    assert (await BluezPairing.open(bluez, None)).adapter == "hci1"


async def test_devices_of_other_adapters_are_ignored() -> None:
    bluez = FakeBluez()
    bluez.add_device(KEY, paired=True, bonded=True)
    bluez.objects["/org/bluez/hci1/dev_22_33_44_55_66_77"] = {
        "org.bluez.Device1": {"Address": "22:33:44:55:66:77"}
    }
    pairing = await BluezPairing.open(bluez, None)
    assert [device.address for device in await pairing.devices()] == [KEY]
    (device,) = await pairing.devices()
    assert device.fido and device.has_bond and not device.advertising


async def test_a_bluez_call_that_never_returns_times_out() -> None:
    bluez = FakeBluez()

    async def hang(_path: str) -> None:
        await asyncio.sleep(3600)

    bluez._StartDiscovery = hang  # type: ignore[assignment,method-assign]
    pairing = BluezPairing(bluez, "/org/bluez/hci0", call_timeout=0.05)
    with pytest.raises(BluetoothError) as raised:
        await pairing.start_discovery()
    assert raised.value.name == TIMED_OUT


def test_every_pairing_error_gets_advice() -> None:
    for name in (
        "org.bluez.Error.AuthenticationFailed",
        "org.bluez.Error.AuthenticationCanceled",
        "org.bluez.Error.ConnectionAttemptFailed",
        TIMED_OUT,
    ):
        assert "run setup again" in pairing_advice(BluetoothError(name, "x"))
    assert pairing_advice(BluetoothError("org.bluez.Error.Failed", "boom")) == (
        "pairing failed: boom (org.bluez.Error.Failed)."
    )
