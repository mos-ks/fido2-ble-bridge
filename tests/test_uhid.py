import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from fido2_ble_bridge import uhid

C_PROBE = r"""
#include <stddef.h>
#include <stdio.h>
#include <linux/uhid.h>
int main(void) {
    printf("%zu %zu %zu %zu %zu %zu\n",
        sizeof(struct uhid_event),
        offsetof(struct uhid_event, u.create2.rd_size),
        offsetof(struct uhid_event, u.create2.rd_data),
        offsetof(struct uhid_event, u.output.size),
        offsetof(struct uhid_event, u.output.rtype),
        offsetof(struct uhid_event, u.input2.data));
    return 0;
}
"""


@pytest.mark.skipif(
    shutil.which("cc") is None or not Path("/usr/include/linux/uhid.h").exists(),
    reason="needs a C compiler and kernel headers",
)
def test_struct_layout_matches_kernel_header(tmp_path: Path) -> None:
    source = tmp_path / "probe.c"
    source.write_text(C_PROBE)
    binary = tmp_path / "probe"
    subprocess.run(["cc", "-o", str(binary), str(source)], check=True)
    sizes = [
        int(v)
        for v in subprocess.run(
            [str(binary)], check=True, capture_output=True, text=True
        ).stdout.split()
    ]

    create = uhid.pack_create2(
        name="n", phys="p", uniq="u", bus=3, vendor=1, product=2, version=3, country=0,
        descriptor=b"\xaa",
    )  # fmt: skip
    assert sizes[0] == uhid.EVENT_SIZE
    assert create[sizes[1] : sizes[1] + 2] == struct.pack("=H", 1)
    assert create[sizes[2] :] == b"\xaa"
    assert sizes[3] == 4 + uhid.UHID_DATA_MAX
    assert sizes[4] == 4 + uhid.UHID_DATA_MAX + 2
    assert sizes[5] == 6


def test_create2_carries_the_fido_descriptor_and_usb_bus() -> None:
    event = uhid.pack_create2(
        name="FIDO2 BLE bridge", phys="", uniq="", bus=uhid.BUS_USB, vendor=0, product=0,
        version=0, country=0, descriptor=uhid.FIDO_REPORT_DESCRIPTOR,
    )  # fmt: skip
    kind, name, _phys, _uniq, rd_size, bus = struct.unpack_from("=I128s64s64sHH", event)
    assert kind == uhid.UHID_CREATE2
    assert name.rstrip(b"\0") == b"FIDO2 BLE bridge"
    assert bus == uhid.BUS_USB
    assert event[-rd_size:] == uhid.FIDO_REPORT_DESCRIPTOR
    assert uhid.FIDO_REPORT_DESCRIPTOR[:3] == b"\x06\xd0\xf1"


def test_names_are_truncated_to_leave_a_terminator() -> None:
    event = uhid.pack_create2(
        name="x" * 300, phys="", uniq="", bus=3, vendor=0, product=0, version=0, country=0,
        descriptor=b"",
    )  # fmt: skip
    assert event[4 + 127] == 0


def test_input2_is_size_prefixed() -> None:
    assert uhid.pack_input2(b"\x01\x02") == struct.pack("=IH", uhid.UHID_INPUT2, 2) + b"\x01\x02"


def output_event(data: bytes, rtype: int = uhid.UHID_OUTPUT_REPORT) -> bytes:
    body = data.ljust(uhid.UHID_DATA_MAX, b"\0") + struct.pack("=HB", len(data), rtype)
    return struct.pack("=I", uhid.UHID_OUTPUT) + body


def test_parse_output_event() -> None:
    event = uhid.parse_event(output_event(b"\x00" + b"\x11" * 64))
    assert event == uhid.OutputEvent(b"\x00" + b"\x11" * 64, uhid.UHID_OUTPUT_REPORT)


def test_parse_lifecycle_and_report_requests() -> None:
    assert uhid.parse_event(struct.pack("=I", uhid.UHID_CLOSE)) == uhid.LifecycleEvent(
        uhid.UHID_CLOSE
    )
    get = struct.pack("=IIBB", uhid.UHID_GET_REPORT, 7, 0, 0)
    assert uhid.parse_event(get) == uhid.GetReportEvent(7)
    assert uhid.parse_event(b"\x01") is None
    assert uhid.parse_event(struct.pack("=I", 99)) is None


@pytest.mark.parametrize(
    ("data", "rtype", "expected"),
    [
        (b"\x00" + b"\x22" * 64, uhid.UHID_OUTPUT_REPORT, b"\x22" * 64),
        (b"\x22" * 64, uhid.UHID_OUTPUT_REPORT, b"\x22" * 64),
        (b"\x05" + b"\x22" * 64, uhid.UHID_OUTPUT_REPORT, None),
        (b"\x22" * 10, uhid.UHID_OUTPUT_REPORT, None),
        (b"\x00" + b"\x22" * 64, 0, None),
    ],
)
def test_output_report_payload(data: bytes, rtype: int, expected: bytes | None) -> None:
    assert uhid.output_report_payload(uhid.OutputEvent(data, rtype), 64) == expected


def test_read_events_is_bounded_per_call() -> None:
    reader, writer = os.pipe()
    os.set_blocking(reader, False)
    device = uhid.UhidDevice.__new__(uhid.UhidDevice)
    device._fd = reader
    device._created = False
    close_event = struct.pack("=I", uhid.UHID_CLOSE).ljust(uhid.EVENT_SIZE, b"\0")
    for _ in range(5):
        os.write(writer, close_event)
    # A pipe returns whatever is buffered, so read one event-sized chunk per call.
    assert len(device.read_events(limit=2)) == 2
    assert len(device.read_events(limit=64)) == 3
    os.close(writer)
    os.close(reader)
