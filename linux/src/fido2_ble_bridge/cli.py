"""Command line: `run` the daemon, `scan` for keys, `check` a configured key end to end."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from .ble_link import ErrorResponse, FidoBleLink, KeyUnavailable, LinkError
from .bluez import BleakGattConnector, scan_fido_devices
from .config import DEFAULT_CONFIG_PATH, Config, ConfigError, load_config
from .daemon import run

CTAP2_GET_INFO = b"\x04"


async def _scan(timeout: float, adapter: str | None) -> int:
    print(f"Scanning {timeout:g}s for devices advertising the FIDO BLE service...")
    devices = await scan_fido_devices(timeout, adapter)
    if not devices:
        print("None found. Wake the key or put it in pairing mode, then scan again.")
        return 1
    for address, name, bonded in devices:
        print(f"{address}  {name or '(no name)'}  {'bonded' if bonded else 'not bonded'}")
    return 0


async def _check(config: Config) -> int:
    link = FidoBleLink(BleakGattConnector(config.address, config.adapter), idle_disconnect=0)
    print(f"Waiting up to {config.connect_timeout:g}s for {config.address}: wake the key now.")
    try:
        response = await link.request(
            CTAP2_GET_INFO,
            connect_timeout=config.connect_timeout,
            on_keepalive=lambda _status: None,
            cancelled=asyncio.Event(),
        )
    except (KeyUnavailable, LinkError) as exc:
        print(f"FAIL: {exc}")
        return 1
    finally:
        await link.close()
    if isinstance(response, ErrorResponse):
        print(f"FAIL: authenticator answered with BLE error 0x{response.code:02x}")
        return 1
    if not response.data or response.data[0] != 0:
        status = f"0x{response.data[0]:02x}" if response.data else "empty"
        print(f"FAIL: getInfo returned CTAP status {status}")
        return 1
    print(
        "OK: bonded and encrypted link, FIDO2 selected, "
        f"fragment size {link.fragment_size}, getInfo returned {len(response.data) - 1} bytes."
    )
    return 0


def configure_logging(*, verbose: bool) -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("fido2_ble_bridge").setLevel(logging.DEBUG if verbose else logging.INFO)
    # bleak logs raw GATT reads and writes (CTAP payloads, PIN protocol data) at DEBUG.
    for library in ("bleak", "dbus_fast"):
        logging.getLogger(library).setLevel(logging.WARNING)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fido2-ble-bridge",
        description="Expose a bonded Bluetooth LE FIDO2 key as a virtual USB FIDO device.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    commands = parser.add_subparsers(dest="command", required=True)

    run_cmd = commands.add_parser("run", help="run the bridge (normally started by systemd)")
    run_cmd.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)

    scan_cmd = commands.add_parser("scan", help="list nearby keys advertising FIDO over BLE")
    scan_cmd.add_argument("--timeout", type=float, default=10.0)
    scan_cmd.add_argument("--adapter", default=None, help="e.g. hci0")

    check_cmd = commands.add_parser("check", help="connect to the configured key and query it")
    check_cmd.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)

    args = parser.parse_args(argv)
    configure_logging(verbose=args.verbose)
    try:
        if args.command == "scan":
            return asyncio.run(_scan(args.timeout, args.adapter))
        config = load_config(args.config)
        if args.command == "check":
            return asyncio.run(_check(config))
        asyncio.run(run(config))
        return 0
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
