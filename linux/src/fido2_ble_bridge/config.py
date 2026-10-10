"""Daemon configuration, loaded from TOML and validated strictly (unknown keys are errors)."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = Path("/etc/fido2-ble-bridge/config.toml")
# The pam_u2f authfile the shipped PAM profile names.
DEFAULT_MAPPINGS_PATH = Path("/etc/fido2-ble-bridge/u2f_mappings")
# The address in the example config; the installer and setup treat it as "not configured yet".
PLACEHOLDER_ADDRESS = "AA:BB:CC:DD:EE:FF"
_ADDRESS = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")
_ADAPTER = re.compile(r"^hci[0-9]{1,3}$")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Config:
    address: str
    adapter: str | None = None
    connect_timeout: float = 10.0
    request_timeout: float = 60.0
    idle_disconnect: float = 10.0
    device_name: str = "FIDO2 BLE bridge"


def _number(raw: dict[str, Any], key: str, default: float, low: float, high: float) -> float:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ConfigError(f"{key} must be a number")
    if not low <= value <= high:
        raise ConfigError(f"{key} must be between {low:g} and {high:g}")
    return float(value)


def parse_address(value: object) -> str:
    """A Bluetooth address in the upper-case form BlueZ reports, or ConfigError."""
    if not isinstance(value, str) or not _ADDRESS.match(value.upper()):
        raise ConfigError("address must be a Bluetooth address like AA:BB:CC:DD:EE:FF")
    return value.upper()


def parse_config(raw: dict[str, Any]) -> Config:
    unknown = set(raw) - {f.name for f in fields(Config)}
    if unknown:
        raise ConfigError(f"unknown keys: {', '.join(sorted(unknown))}")

    address = parse_address(raw.get("address"))

    adapter = raw.get("adapter")
    if adapter is not None and (not isinstance(adapter, str) or not _ADAPTER.match(adapter)):
        raise ConfigError("adapter must look like hci0")

    device_name = raw.get("device_name", Config.device_name)
    if not isinstance(device_name, str) or not 0 < len(device_name.encode()) < 128:
        raise ConfigError("device_name must be a non-empty string under 128 bytes")

    return Config(
        address=address,
        adapter=adapter,
        connect_timeout=_number(raw, "connect_timeout", Config.connect_timeout, 1, 120),
        request_timeout=_number(raw, "request_timeout", Config.request_timeout, 5, 300),
        idle_disconnect=_number(raw, "idle_disconnect", Config.idle_disconnect, 0, 600),
        device_name=device_name,
    )


def load_config(path: Path) -> Config:
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from exc
    return parse_config(raw)
