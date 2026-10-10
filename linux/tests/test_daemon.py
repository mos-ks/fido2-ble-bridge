import asyncio
import errno
import os
import socket
from typing import NoReturn

import pytest
from fakes import SimulatedConnector

from fido2_ble_bridge import daemon
from fido2_ble_bridge.ble_link import FidoBleLink
from fido2_ble_bridge.uhid import UhidDevice, UhidEvent


async def test_a_failing_uhid_read_ends_the_daemon_with_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Returning normally would let the service exit with status 0, which systemd's
    # Restart=on-failure does not restart.
    ours, kernel = socket.socketpair()
    device = UhidDevice(fd=ours.detach())

    def failing_read(limit: int = 64) -> list[UhidEvent]:
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(device, "read_events", failing_read)
    link = FidoBleLink(SimulatedConnector())
    kernel.send(b"\0")  # makes the descriptor readable
    try:
        with pytest.raises(OSError, match="reading /dev/uhid failed"):
            async with asyncio.timeout(2.0):
                await daemon.serve_device(
                    device, link, name="test", connect_timeout=1.0, stop=asyncio.Event()
                )
    finally:
        device.close()
        kernel.close()
        await link.close()


@pytest.mark.parametrize(
    ("error", "hint"),
    [
        (FileNotFoundError(errno.ENOENT, "No such file or directory", "/dev/uhid"), "modprobe"),
        (PermissionError(errno.EACCES, "Permission denied", "/dev/uhid"), "systemctl start"),
    ],
)
def test_opening_uhid_explains_common_failures(
    monkeypatch: pytest.MonkeyPatch, error: OSError, hint: str
) -> None:
    def fail(*_args: object, **_kwargs: object) -> NoReturn:
        raise error

    monkeypatch.setattr(daemon, "inherited_fd", lambda _name: None)
    monkeypatch.setattr(daemon, "UhidDevice", fail)
    with pytest.raises(OSError, match=hint):
        daemon.open_uhid()


def test_open_uhid_adopts_the_descriptor_systemd_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    reader, writer = os.pipe()
    names: list[str] = []

    def inherited(name: str) -> int:
        names.append(name)
        return reader

    monkeypatch.setattr(daemon, "inherited_fd", inherited)
    device = daemon.open_uhid()
    assert device.fileno() == reader
    assert names == [daemon.UHID_FD_NAME]
    device.close()
    os.close(writer)
