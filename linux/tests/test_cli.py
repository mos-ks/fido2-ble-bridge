import errno
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, NoReturn

import pytest
from bleak.exc import BleakError
from fakes import SimulatedConnector

from fido2_ble_bridge import cli, daemon, setup_wizard
from fido2_ble_bridge.bluez import FoundKey
from fido2_ble_bridge.cli import configure_logging, main
from fido2_ble_bridge.setup_wizard import SetupOptions

ADDRESS = "AA:BB:CC:DD:EE:FF"


def test_verbose_logging_never_enables_bleak_payload_logs() -> None:
    configure_logging(verbose=True)
    assert logging.getLogger("fido2_ble_bridge").isEnabledFor(logging.DEBUG)
    assert not logging.getLogger("bleak.backends.bluezdbus.client").isEnabledFor(logging.DEBUG)
    assert not logging.getLogger("dbus_fast").isEnabledFor(logging.DEBUG)


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(f'address = "{ADDRESS}"\nadapter = "hci1"\nconnect_timeout = 2\n')
    return path


def use_key(
    monkeypatch: pytest.MonkeyPatch, connector: SimulatedConnector
) -> list[tuple[str, str | None]]:
    """Route the configured key to a simulated one; returns the (address, adapter) opened."""
    opened: list[tuple[str, str | None]] = []

    def connect_to(address: str, adapter: str | None = None) -> SimulatedConnector:
        opened.append((address, adapter))
        return connector

    monkeypatch.setattr(daemon, "BleakGattConnector", connect_to)
    return opened


def test_check_reports_a_working_key(
    monkeypatch: pytest.MonkeyPatch, config_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    connector = SimulatedConnector()
    opened = use_key(monkeypatch, connector)
    assert main(["check", "--config", str(config_path)]) == 0
    out = capsys.readouterr().out
    assert f"Waiting up to 2s for {ADDRESS}" in out
    assert "OK: bonded and encrypted link, FIDO2 selected, fragment size 128," in out
    assert opened == [(ADDRESS, "hci1")]
    assert not connector.last.connected


@pytest.mark.parametrize(
    ("key", "message"),
    [
        ({"bonded": False}, "FAIL: simulated key is not bonded"),
        ({"error_code": b"\x06"}, "FAIL: authenticator answered with BLE error 0x06"),
        ({"responder": lambda _data: b"\x01"}, "FAIL: getInfo returned CTAP status 0x01"),
        ({"responder": lambda _data: b""}, "FAIL: getInfo returned CTAP status empty"),
    ],
)
def test_check_reports_failures(
    monkeypatch: pytest.MonkeyPatch,
    config_path: Path,
    capsys: pytest.CaptureFixture[str],
    key: dict[str, Any],
    message: str,
) -> None:
    use_key(monkeypatch, SimulatedConnector(**key))
    assert main(["check", "--config", str(config_path)]) == 1
    assert message in capsys.readouterr().out


def test_unreadable_config_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["check", "--config", str(tmp_path / "missing.toml")]) == 2
    assert "cannot read" in capsys.readouterr().err


def test_scan_lists_keys_with_their_bond_state(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def scan(timeout: float, adapter: str | None) -> list[FoundKey]:
        assert (timeout, adapter) == (3.0, "hci0")
        return [
            FoundKey(ADDRESS, "Key", True, "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF"),
            FoundKey("11:22:33:44:55:66", None, False, "/org/bluez/hci0/dev_11_22_33_44_55_66"),
        ]

    monkeypatch.setattr(cli, "scan_fido_devices", scan)
    assert main(["scan", "--timeout", "3", "--adapter", "hci0"]) == 0
    out = capsys.readouterr().out
    assert f"{ADDRESS}  Key  bonded\n" in out
    assert "11:22:33:44:55:66  (no name)  not bonded\n" in out


def test_scan_prints_advertised_names_harmlessly(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Anyone nearby picks the name; it must not reach the terminal as escape sequences.
    async def scan(_timeout: float, _adapter: str | None) -> list[FoundKey]:
        return [FoundKey(ADDRESS, "\x1b[2K\rKey\x1b]0;x\x07", False, "/org/bluez/hci0/dev_x")]

    monkeypatch.setattr(cli, "scan_fido_devices", scan)
    assert main(["scan"]) == 0
    assert f"{ADDRESS}  ?[2K?Key?]0;x?  not bonded\n" in capsys.readouterr().out


def test_scan_that_finds_nothing_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def scan(_timeout: float, _adapter: str | None) -> list[FoundKey]:
        return []

    monkeypatch.setattr(cli, "scan_fido_devices", scan)
    assert main(["scan"]) == 1
    assert "None found" in capsys.readouterr().out


@pytest.mark.parametrize(
    "error",
    [
        BleakError("No Bluetooth adapters found."),
        FileNotFoundError(errno.ENOENT, "No such file or directory"),
    ],
)
def test_scan_without_bluetooth_is_an_error_not_a_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], error: Exception
) -> None:
    async def scan(_timeout: float, _adapter: str | None) -> NoReturn:
        raise error

    monkeypatch.setattr(cli, "scan_fido_devices", scan)
    assert main(["scan"]) == 1
    assert "error: Bluetooth is not available:" in capsys.readouterr().err


def test_run_without_uhid_explains_how_to_load_it(
    monkeypatch: pytest.MonkeyPatch, config_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def missing(*_args: object, **_kwargs: object) -> NoReturn:
        raise FileNotFoundError(errno.ENOENT, "No such file or directory", "/dev/uhid")

    use_key(monkeypatch, SimulatedConnector())
    monkeypatch.setattr(daemon, "inherited_fd", lambda _name: None)
    monkeypatch.setattr(daemon, "UhidDevice", missing)
    assert main(["run", "--config", str(config_path)]) == 1
    assert "modprobe uhid" in capsys.readouterr().err


def test_setup_passes_its_options_on(monkeypatch: pytest.MonkeyPatch) -> None:
    received: list[SetupOptions] = []

    def run_setup(options: SetupOptions) -> int:
        received.append(options)
        return 0

    monkeypatch.setattr(setup_wizard, "run_setup", run_setup)
    argv = ["setup", "--user", "bob", "--address", "aa:bb:cc:dd:ee:ff", "--yes", "--no-pam"]
    assert main(argv) == 0
    assert received == [SetupOptions(user="bob", address=ADDRESS, yes=True, no_pam=True)]


def test_the_service_does_not_load_setup_s_pairing_and_pam_code() -> None:
    # `run` imports cli; pairing.py and pam.py (with ctypes) are for setup only. A fresh
    # interpreter, because this test session has imported them already.
    code = (
        "import sys, fido2_ble_bridge.cli; "
        "print(' '.join(name for name in ('fido2_ble_bridge.setup_wizard', "
        "'fido2_ble_bridge.pairing', 'fido2_ble_bridge.pam', 'ctypes') if name in sys.modules))"
    )
    done = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=True
    )
    assert done.stdout.strip() == ""


def test_setup_rejects_a_malformed_address(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exited:
        main(["setup", "--address", "not-an-address"])
    assert exited.value.code == 2
    assert "Bluetooth address like AA:BB:CC:DD:EE:FF" in capsys.readouterr().err


def test_setup_without_root_stops_before_changing_anything(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    assert main(["setup", "--user", "nobody"]) == 1
    out = capsys.readouterr().out
    assert "must run as root: sudo fido2-ble-bridge setup" in out
    assert "Nothing on this system was changed." in out
