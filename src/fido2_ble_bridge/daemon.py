"""The long-running service: virtual HID device, bridge and BLE link wired to one event loop."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal

from .ble_link import FidoBleLink
from .bluez import BleakGattConnector
from .bridge import AuthenticatorLink, Bridge
from .config import Config
from .ctaphid import PACKET_SIZE
from .uhid import (
    UHID_CLOSE,
    GetReportEvent,
    LifecycleEvent,
    OutputEvent,
    SetReportEvent,
    UhidDevice,
    output_report_payload,
)

log = logging.getLogger(__name__)

TICK_INTERVAL = 0.25
SHUTDOWN_GRACE = 5.0


async def serve_device(
    uhid: UhidDevice,
    link: AuthenticatorLink,
    *,
    name: str,
    connect_timeout: float,
    stop: asyncio.Event,
) -> None:
    uhid.create(name=name, phys="fido2-ble-bridge")
    bridge = Bridge(uhid, link, connect_timeout=connect_timeout)
    loop = asyncio.get_running_loop()

    def on_readable() -> None:
        try:
            events = uhid.read_events()
        except OSError as exc:
            log.error("reading /dev/uhid failed: %s", exc)
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
            bridge.tick()

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


async def run(config: Config) -> None:
    link = FidoBleLink(
        BleakGattConnector(config.address, config.adapter),
        idle_disconnect=config.idle_disconnect,
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    try:
        with UhidDevice() as uhid:
            await serve_device(
                uhid,
                link,
                name=config.device_name,
                connect_timeout=config.connect_timeout,
                stop=stop,
            )
    finally:
        await link.close()
