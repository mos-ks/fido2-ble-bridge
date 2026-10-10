"""Command line: `run` the daemon, `scan` for keys, `check` the key, `setup` everything."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from bleak.exc import BleakError

from .bluez import scan_fido_devices
from .config import DEFAULT_CONFIG_PATH, Config, ConfigError, load_config, parse_address
from .console import device_name
from .daemon import check_key, run_daemon


async def _scan(timeout: float, adapter: str | None) -> int:
    print(f"Scanning {timeout:g}s for devices advertising the FIDO BLE service...")
    try:
        keys = await scan_fido_devices(timeout, adapter)
    except (BleakError, OSError) as exc:
        # No adapter, adapter powered off, or no system D-Bus.
        print(f"error: Bluetooth is not available: {exc}", file=sys.stderr)
        return 1
    if not keys:
        print("None found. Wake the key or put it in pairing mode, then scan again.")
        return 1
    for key in keys:
        bonded = "bonded" if key.bonded else "not bonded"
        print(f"{key.address}  {device_name(key.name)}  {bonded}")
    return 0


async def _check(config: Config) -> int:
    print(f"Waiting up to {config.connect_timeout:g}s for {config.address}: wake the key now.")
    result = await check_key(config)
    print(f"{'OK' if result.ok else 'FAIL'}: {result.message}")
    return 0 if result.ok else 1


def configure_logging(*, verbose: bool) -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("fido2_ble_bridge").setLevel(logging.DEBUG if verbose else logging.INFO)
    # bleak logs raw GATT reads and writes (CTAP payloads, PIN protocol data) at DEBUG.
    for library in ("bleak", "dbus_fast"):
        logging.getLogger(library).setLevel(logging.WARNING)


def _address(text: str) -> str:
    try:
        return parse_address(text)
    except ConfigError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


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

    setup_cmd = commands.add_parser(
        "setup",
        help="guided setup (run with sudo): pair the key, start the bridge, register the key "
        "for your account, test it and enable it for logins",
    )
    setup_cmd.add_argument(
        "--user", help="account to set up (default: the one that ran sudo; root only by name)"
    )
    setup_cmd.add_argument("--address", type=_address, help="the key's Bluetooth address")
    setup_cmd.add_argument(
        "--yes", action="store_true", help="install missing packages without asking"
    )
    setup_cmd.add_argument(
        "--no-pam", action="store_true", help="do everything except enabling the key in PAM"
    )

    args = parser.parse_args(argv)
    configure_logging(verbose=args.verbose)
    if args.command == "setup":
        # Imported here only: setup brings the pairing agent, the PAM bindings and ctypes, which
        # the sandboxed `run` service must never load.
        from .setup_wizard import SetupOptions, run_setup  # noqa: PLC0415

        # Setup talks to the user itself; the bridge's info logs would only clutter that.
        logging.getLogger("fido2_ble_bridge").setLevel(
            logging.DEBUG if args.verbose else logging.WARNING
        )
        options = SetupOptions(
            user=args.user, address=args.address, yes=args.yes, no_pam=args.no_pam
        )
        return run_setup(options)
    try:
        if args.command == "scan":
            return asyncio.run(_scan(args.timeout, args.adapter))
        config = load_config(args.config)
        if args.command == "check":
            return asyncio.run(_check(config))
        asyncio.run(run_daemon(config))
        return 0
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        # /dev/uhid missing, not accessible or failing: exit non-zero so systemd restarts us.
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
