from pathlib import Path
from typing import Any

import pytest

from fido2_ble_bridge.ble_link import KeyNotTrusted
from fido2_ble_bridge.bluez import check_bond
from fido2_ble_bridge.config import Config, ConfigError, load_config, parse_config

ADDRESS = "AA:BB:CC:DD:EE:FF"


def test_minimal_config_gets_defaults_and_normalised_address() -> None:
    assert parse_config({"address": ADDRESS.lower()}) == Config(address=ADDRESS)


def test_full_config() -> None:
    config = parse_config(
        {
            "address": ADDRESS,
            "adapter": "hci1",
            "connect_timeout": 15,
            "request_timeout": 90,
            "idle_disconnect": 0,
            "device_name": "My key",
        }
    )
    assert config == Config(
        address=ADDRESS,
        adapter="hci1",
        connect_timeout=15.0,
        request_timeout=90.0,
        idle_disconnect=0.0,
        device_name="My key",
    )


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ({}, "address"),
        ({"address": "AA:BB:CC:DD:EE"}, "address"),
        ({"address": 42}, "address"),
        ({"address": ADDRESS, "adress": "typo"}, "unknown keys: adress"),
        ({"address": ADDRESS, "adapter": "../hci0"}, "adapter"),
        ({"address": ADDRESS, "connect_timeout": True}, "connect_timeout"),
        ({"address": ADDRESS, "connect_timeout": "10"}, "connect_timeout"),
        ({"address": ADDRESS, "connect_timeout": 0.5}, "between"),
        ({"address": ADDRESS, "idle_disconnect": 601}, "between"),
        ({"address": ADDRESS, "request_timeout": 1}, "between"),
        ({"address": ADDRESS, "device_name": ""}, "device_name"),
        ({"address": ADDRESS, "device_name": "x" * 128}, "device_name"),
    ],
)
def test_invalid_configs_are_rejected(raw: dict[str, Any], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_config(raw)


def test_load_config_reports_unreadable_and_invalid_files(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "missing.toml")
    bad = tmp_path / "bad.toml"
    bad.write_text("address = ")
    with pytest.raises(ConfigError, match="not valid TOML"):
        load_config(bad)
    good = tmp_path / "good.toml"
    good.write_text(f'address = "{ADDRESS}"\n')
    assert load_config(good).address == ADDRESS


def test_bond_check_accepts_only_the_configured_bonded_device() -> None:
    check_bond({"Address": ADDRESS, "Paired": True, "Bonded": True}, ADDRESS)
    for props in (
        {"Address": ADDRESS, "Paired": True, "Bonded": False},
        {"Address": ADDRESS, "Paired": False, "Bonded": True},
        {"Address": ADDRESS},
        {"Address": "11:22:33:44:55:66", "Paired": True, "Bonded": True},
    ):
        with pytest.raises(KeyNotTrusted):
            check_bond(props, ADDRESS)
