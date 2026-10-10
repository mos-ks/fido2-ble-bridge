"""The long-running service: virtual HID device, bridge and BLE link wired to one event loop."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from dataclasses import dataclass

from .ble_link import CTAP2_GET_INFO, ErrorResponse, FidoBleLink, KeyUnavailable, LinkError
from .bluez import BleakGattConnector
from .bridge import AuthenticatorLink, Bridge
from .config import Config
from .ctaphid import PACKET_SIZE
from .uhid import (
    BRIDGE_PHYS,
    UHID_CLOSE,
    GetReportEvent,
    LifecycleEvent,
    OutputEvent,
    SetReportEvent,
    UhidDevice,
    inherited_fd,
    output_report_payload,
)

log = logging.getLogger(__name__)

TICK_INTERVAL = 0.25
SHUTDOWN_GRACE = 5.0
# The name the systemd unit gives the /dev/uhid descriptor it opens for the service
# (OpenFile=/dev/uhid:uhid).
UHID_FD_NAME = "uhid"


def make_link(config: Config, *, idle_disconnect: float | None = None) -> FidoBleLink:
    """The BLE link to the configured key, with the configured timeouts."""
    return FidoBleLink(
        BleakGattConnector(config.address, config.adapter),
        idle_disconnect=config.idle_disconnect if idle_disconnect is None else idle_disconnect,
        request_timeout=config.request_timeout,
    )


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    message: str
    error: KeyUnavailable | LinkError | None = None
    """Why the key could not be reached at all, if that was the failure."""


async def check_key(config: Config, *, connect_timeout: float | None = None) -> CheckResult:
    """Connect to the configured key and run getInfo, which needs no touch or fingerprint."""
    link = make_link(config, idle_disconnect=0)
    try:
        response = await link.request(
            CTAP2_GET_INFO,
            connect_timeout=config.connect_timeout if connect_timeout is None else connect_timeout,
            on_keepalive=lambda _status: None,
            cancelled=asyncio.Event(),
        )
    except (KeyUnavailable, LinkError) as exc:
        return CheckResult(ok=False, message=str(exc), error=exc)
    finally:
        await link.close()
    if isinstance(response, ErrorResponse):
        return CheckResult(False, f"authenticator answered with BLE error 0x{response.code:02x}")
    if not response.data or response.data[0] != 0:
        status = f"0x{response.data[0]:02x}" if response.data else "empty"
        return CheckResult(False, f"getInfo returned CTAP status {status}")
    return CheckResult(
        True,
        "bonded and encrypted link, FIDO2 selected, "
        f"fragment size {link.fragment_size}, getInfo returned {len(response.data) - 1} bytes.",
    )


def open_uhid() -> UhidDevice:
    """The /dev/uhid descriptor systemd passed in, or else /dev/uhid itself (root only)."""
    fd = inherited_fd(UHID_FD_NAME)
    if fd is not None:
        return UhidDevice(fd=fd)
    try:
        return UhidDevice()
    except FileNotFoundError as exc:
        raise OSError(
            "/dev/uhid does not exist; load the uhid kernel module (sudo modprobe uhid)"
        ) from exc
    except PermissionError as exc:
        raise OSError(
            "/dev/uhid is root-only; run the bridge as its systemd service "
            "(sudo systemctl start fido2-ble-bridge)"
        ) from exc


async def serve_device(
    uhid: UhidDevice,
    link: AuthenticatorLink,
    *,
    name: str,
    connect_timeout: float,
    stop: asyncio.Event,
) -> None:
    """Serve the virtual device until `stop` is set.

    Raises OSError if reading /dev/uhid fails, so the service exits with an error and systemd
    restarts it (Restart=on-failure does not restart after a clean exit).
    """
    uhid.create(name=name, phys=BRIDGE_PHYS)
    bridge = Bridge(uhid, link, connect_timeout=connect_timeout)
    loop = asyncio.get_running_loop()
    read_error: OSError | None = None

    def on_readable() -> None:
        nonlocal read_error
        try:
            events = uhid.read_events()
        except OSError as exc:
            read_error = read_error or exc
            stop.set()
            return
        for event in events:
            if isinstance(event, OutputEvent):
                packet = output_report_payload(event, PACKET_SIZE)
                if packet is not None:
                    bridge.on_output_report(packet)
            elif isinstance(event, GetReportEvent):
                uhid.reply_get_report(event.request_id)
            elif isinstance(event, SetReportEvent):
                uhid.reply_set_report(event.request_id)
            elif isinstance(event, LifecycleEvent) and event.kind == UHID_CLOSE:
                bridge.on_all_closed()

    async def tick() -> None:
        while True:
            await asyncio.sleep(TICK_INTERVAL)
            try:
                bridge.tick()
            except Exception:
                log.exception("CTAPHID timer failed")

    loop.add_reader(uhid.fileno(), on_readable)
    ticker = asyncio.create_task(tick())
    log.info("virtual FIDO device %r is up", name)
    try:
        await stop.wait()
    finally:
        loop.remove_reader(uhid.fileno())
        ticker.cancel()
        bridge.on_all_closed()
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(SHUTDOWN_GRACE):
                await bridge.drain()
    if read_error is not None:
        raise OSError(f"reading /dev/uhid failed: {read_error}") from read_error


async def run_daemon(config: Config) -> None:
    link = make_link(config)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    try:
        with open_uhid() as uhid:
            await serve_device(
                uhid,
                link,
                name=config.device_name,
                connect_timeout=config.connect_timeout,
                stop=stop,
            )
    finally:
        await link.close()
