"""Linux uhid: a virtual HID device backed by this process (linux/uhid.h)."""

from __future__ import annotations

import errno
import logging
import os
import struct
from dataclasses import dataclass
from types import TracebackType

log = logging.getLogger(__name__)

UHID_DESTROY = 1
UHID_START = 2
UHID_STOP = 3
UHID_OPEN = 4
UHID_CLOSE = 5
UHID_OUTPUT = 6
UHID_GET_REPORT = 9
UHID_GET_REPORT_REPLY = 10
UHID_CREATE2 = 11
UHID_INPUT2 = 12
UHID_SET_REPORT = 13
UHID_SET_REPORT_REPLY = 14

UHID_OUTPUT_REPORT = 1
UHID_DATA_MAX = 4096
HID_MAX_DESCRIPTOR_SIZE = 4096
_CREATE2_HEADER = struct.Struct("=I128s64s64sHHIIII")
# sizeof(struct uhid_event): the u32 type plus the union. The union holds an unpacked __u64
# (uhid_start_req), so its size is the largest member, uhid_create2_req, rounded up to 8.
_UNION_SIZE = -(-(_CREATE2_HEADER.size - 4 + HID_MAX_DESCRIPTOR_SIZE) // 8) * 8
EVENT_SIZE = 4 + _UNION_SIZE

BUS_USB = 0x03

# CTAP 2.1 section 11.2.8.2: usage page 0xF1D0, usage 0x01, 64-byte input and output reports.
FIDO_REPORT_DESCRIPTOR = bytes(
    [
        0x06, 0xD0, 0xF1,  # Usage Page (FIDO Alliance)
        0x09, 0x01,        # Usage (CTAPHID)
        0xA1, 0x01,        # Collection (Application)
        0x09, 0x20,        #   Usage (Input Report Data)
        0x15, 0x00,        #   Logical Minimum (0)
        0x26, 0xFF, 0x00,  #   Logical Maximum (255)
        0x75, 0x08,        #   Report Size (8)
        0x95, 0x40,        #   Report Count (64)
        0x81, 0x02,        #   Input (Data, Variable, Absolute)
        0x09, 0x21,        #   Usage (Output Report Data)
        0x15, 0x00,        #   Logical Minimum (0)
        0x26, 0xFF, 0x00,  #   Logical Maximum (255)
        0x75, 0x08,        #   Report Size (8)
        0x95, 0x40,        #   Report Count (64)
        0x91, 0x02,        #   Output (Data, Variable, Absolute)
        0xC0,              # End Collection
    ]
)  # fmt: skip


@dataclass(frozen=True)
class OutputEvent:
    data: bytes
    report_type: int


@dataclass(frozen=True)
class GetReportEvent:
    request_id: int


@dataclass(frozen=True)
class SetReportEvent:
    request_id: int


@dataclass(frozen=True)
class LifecycleEvent:
    kind: int


UhidEvent = OutputEvent | GetReportEvent | SetReportEvent | LifecycleEvent


def pack_create2(
    *,
    name: str,
    phys: str,
    uniq: str,
    bus: int,
    vendor: int,
    product: int,
    version: int,
    country: int,
    descriptor: bytes,
) -> bytes:
    if len(descriptor) > HID_MAX_DESCRIPTOR_SIZE:
        raise ValueError("report descriptor too large")
    return (
        _CREATE2_HEADER.pack(
            UHID_CREATE2,
            name.encode()[:127],
            phys.encode()[:63],
            uniq.encode()[:63],
            len(descriptor),
            bus,
            vendor,
            product,
            version,
            country,
        )
        + descriptor
    )


def pack_input2(report: bytes) -> bytes:
    if len(report) > UHID_DATA_MAX:
        raise ValueError("input report too large")
    return struct.pack("=IH", UHID_INPUT2, len(report)) + report


def pack_get_report_reply(request_id: int, err: int) -> bytes:
    return struct.pack("=IIHH", UHID_GET_REPORT_REPLY, request_id, err, 0)


def pack_set_report_reply(request_id: int, err: int) -> bytes:
    return struct.pack("=IIH", UHID_SET_REPORT_REPLY, request_id, err)


def parse_event(buf: bytes) -> UhidEvent | None:
    if len(buf) < 4:
        return None
    (kind,) = struct.unpack_from("=I", buf)
    if kind == UHID_OUTPUT and len(buf) >= 4 + UHID_DATA_MAX + 3:
        size, report_type = struct.unpack_from("=HB", buf, 4 + UHID_DATA_MAX)
        return OutputEvent(bytes(buf[4 : 4 + min(size, UHID_DATA_MAX)]), report_type)
    if kind == UHID_GET_REPORT and len(buf) >= 8:
        return GetReportEvent(struct.unpack_from("=I", buf, 4)[0])
    if kind == UHID_SET_REPORT and len(buf) >= 8:
        return SetReportEvent(struct.unpack_from("=I", buf, 4)[0])
    if kind in (UHID_START, UHID_STOP, UHID_OPEN, UHID_CLOSE):
        return LifecycleEvent(kind)
    return None


def output_report_payload(event: OutputEvent, report_size: int) -> bytes | None:
    """The report body of a hidraw write; hidraw prefixes report ID 0 for unnumbered reports."""
    if event.report_type != UHID_OUTPUT_REPORT:
        return None
    if len(event.data) == report_size + 1 and event.data[0] == 0:
        return event.data[1:]
    if len(event.data) == report_size:
        return event.data
    return None


SD_LISTEN_FDS_START = 3


def inherited_fd(name: str) -> int | None:
    """An fd passed by systemd (OpenFile=path:name), per the sd_listen_fds protocol."""
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        return None
    try:
        count = int(os.environ.get("LISTEN_FDS", "0"))
    except ValueError:
        return None
    names = os.environ.get("LISTEN_FDNAMES", "").split(":")
    for index in range(min(count, len(names))):
        if names[index] == name:
            return SD_LISTEN_FDS_START + index
    return None


class UhidDevice:
    """Opens /dev/uhid, or adopts an already-open fd (systemd opens it as root for the
    unprivileged service, so the device node can stay root-only)."""

    def __init__(self, path: str = "/dev/uhid", *, fd: int | None = None) -> None:
        if fd is None:
            self._fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NONBLOCK)
        else:
            os.set_blocking(fd, False)
            os.set_inheritable(fd, False)
            self._fd = fd
        self._created = False

    def __enter__(self) -> UhidDevice:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def fileno(self) -> int:
        return self._fd

    def create(
        self,
        *,
        name: str,
        phys: str = "",
        uniq: str = "",
        vendor: int = 0,
        product: int = 0,
        version: int = 0,
        descriptor: bytes = FIDO_REPORT_DESCRIPTOR,
    ) -> None:
        # libfido2 only enumerates hidraw devices whose HID bus is USB.
        self._write(
            pack_create2(
                name=name,
                phys=phys,
                uniq=uniq,
                bus=BUS_USB,
                vendor=vendor,
                product=product,
                version=version,
                country=0,
                descriptor=descriptor,
            )
        )
        self._created = True

    def send_input(self, report: bytes) -> None:
        self._write(pack_input2(report))

    def reply_get_report(self, request_id: int) -> None:
        self._write(pack_get_report_reply(request_id, errno.EIO))

    def reply_set_report(self, request_id: int) -> None:
        self._write(pack_set_report_reply(request_id, errno.EIO))

    def read_events(self, limit: int = 64) -> list[UhidEvent]:
        """Up to `limit` pending events; the cap keeps a flooding client from starving the loop."""
        events: list[UhidEvent] = []
        for _ in range(limit):
            try:
                buf = os.read(self._fd, EVENT_SIZE)
            except BlockingIOError:
                break
            event = parse_event(buf)
            if event is not None:
                events.append(event)
        return events

    def close(self) -> None:
        if self._fd < 0:
            return
        if self._created:
            try:
                self._write(struct.pack("=I", UHID_DESTROY))
            except OSError as exc:
                log.warning("destroying uhid device failed: %s", exc)
        os.close(self._fd)
        self._fd = -1

    def _write(self, data: bytes) -> None:
        written = os.write(self._fd, data)
        if written != len(data):
            raise OSError(f"short write to uhid: {written} of {len(data)} bytes")
