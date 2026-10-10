"""CTAPHID framing and channel arbitration (CTAP 2.1, section 11.2) as a pure state machine.

The bridge feeds in 64-byte HID output reports and gets back the reports to send and the
complete requests to process. Nothing here does I/O, so the protocol is tested packet by packet.
"""

from __future__ import annotations

import enum
import secrets
import struct
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field

PACKET_SIZE = 64
INIT_DATA_SIZE = PACKET_SIZE - 7
CONT_DATA_SIZE = PACKET_SIZE - 5
MAX_PAYLOAD = INIT_DATA_SIZE + 128 * CONT_DATA_SIZE
BROADCAST_CID = 0xFFFFFFFF
RESERVED_CID = 0
PROTOCOL_VERSION = 2
TYPE_INIT = 0x80
INIT_NONCE_SIZE = 8

CAPABILITY_CBOR = 0x04
CAPABILITY_NMSG = 0x08


class Cmd(enum.IntEnum):
    PING = 0x81
    MSG = 0x83
    LOCK = 0x84
    INIT = 0x86
    WINK = 0x88
    CBOR = 0x90
    CANCEL = 0x91
    KEEPALIVE = 0xBB
    ERROR = 0xBF


class HidError(enum.IntEnum):
    INVALID_CMD = 0x01
    INVALID_PAR = 0x02
    INVALID_LEN = 0x03
    INVALID_SEQ = 0x04
    MSG_TIMEOUT = 0x05
    CHANNEL_BUSY = 0x06
    INVALID_CHANNEL = 0x0B
    OTHER = 0x7F


class KeepaliveStatus(enum.IntEnum):
    PROCESSING = 0x01
    UPNEEDED = 0x02


@dataclass(frozen=True)
class Request:
    """A fully reassembled request the bridge must answer via respond() or fail()."""

    txn: int
    cid: int
    cmd: int
    payload: bytes


@dataclass
class Output:
    reports: list[bytes] = field(default_factory=list)
    requests: list[Request] = field(default_factory=list)
    cancelled: list[int] = field(default_factory=list)


@dataclass
class _Assembling:
    cid: int
    cmd: int
    length: int
    data: bytearray
    next_seq: int
    deadline: float


@dataclass(frozen=True)
class _Processing:
    txn: int
    cid: int
    cmd: int


def fragment(cid: int, cmd: int, payload: bytes) -> list[bytes]:
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(f"payload of {len(payload)} bytes exceeds CTAPHID maximum {MAX_PAYLOAD}")
    reports = [struct.pack(">IBH", cid, cmd, len(payload)) + payload[:INIT_DATA_SIZE]]
    rest = payload[INIT_DATA_SIZE:]
    seq = 0
    while rest:
        reports.append(struct.pack(">IB", cid, seq) + rest[:CONT_DATA_SIZE])
        rest = rest[CONT_DATA_SIZE:]
        seq += 1
    return [report.ljust(PACKET_SIZE, b"\0") for report in reports]


def _random_cid() -> int:
    return secrets.randbits(32)


class CtapHidServer:
    """Device side of CTAPHID: one transaction at a time across all channels.

    `forward` lists the commands handed to the caller as requests. INIT, PING and CANCEL are
    answered here; anything else gets ERR_INVALID_CMD.
    """

    def __init__(
        self,
        *,
        forward: frozenset[int],
        capabilities: int,
        device_version: tuple[int, int, int] = (0, 1, 0),
        assembly_timeout: float = 3.0,
        max_channels: int = 128,
        cid_source: Callable[[], int] = _random_cid,
    ) -> None:
        self._forward = forward
        self._capabilities = capabilities
        self._device_version = device_version
        self._assembly_timeout = assembly_timeout
        self._max_channels = max_channels
        self._cid_source = cid_source
        self._channels: OrderedDict[int, None] = OrderedDict()
        self._active: _Assembling | _Processing | None = None
        self._txn = 0

    @property
    def busy(self) -> bool:
        return self._active is not None

    def handle_report(self, report: bytes, now: float) -> Output:
        out = Output()
        self._expire(now, out)
        if len(report) != PACKET_SIZE:
            return out
        (cid,) = struct.unpack_from(">I", report)
        if report[4] & TYPE_INIT:
            self._handle_init_packet(cid, report, now, out)
        else:
            self._handle_cont_packet(cid, report, out)
        return out

    def tick(self, now: float) -> Output:
        out = Output()
        self._expire(now, out)
        return out

    def respond(self, txn: int, payload: bytes) -> Output:
        out = Output()
        active = self._active
        if not isinstance(active, _Processing) or active.txn != txn:
            return out
        self._active = None
        if len(payload) > MAX_PAYLOAD:
            self._error(active.cid, HidError.OTHER, out)
        else:
            out.reports += fragment(active.cid, active.cmd, payload)
        return out

    def fail(self, txn: int, error: int) -> Output:
        out = Output()
        active = self._active
        if isinstance(active, _Processing) and active.txn == txn:
            self._active = None
            self._error(active.cid, error, out)
        return out

    def keepalive(self, txn: int, status: KeepaliveStatus) -> Output:
        out = Output()
        active = self._active
        if isinstance(active, _Processing) and active.txn == txn:
            out.reports += fragment(active.cid, Cmd.KEEPALIVE, bytes([status]))
        return out

    def abort_all(self) -> Output:
        """Every client has closed the device: drop all channels and in-flight work."""
        out = Output()
        if isinstance(self._active, _Processing):
            out.cancelled.append(self._active.txn)
        self._active = None
        self._channels.clear()
        return out

    def _handle_init_packet(self, cid: int, report: bytes, now: float, out: Output) -> None:
        cmd = report[4]
        length = (report[5] << 8) | report[6]
        data = report[7 : 7 + min(length, INIT_DATA_SIZE)]

        if cmd == Cmd.INIT:
            self._handle_init(cid, length, data, out)
            return
        if cid == BROADCAST_CID or cid not in self._channels:
            self._error(cid, HidError.INVALID_CHANNEL, out)
            return
        if cmd == Cmd.CANCEL:
            active = self._active
            if isinstance(active, _Processing) and active.cid == cid:
                out.cancelled.append(active.txn)
            return
        if self._active is not None:
            if isinstance(self._active, _Assembling) and self._active.cid == cid:
                self._active = None
                self._error(cid, HidError.INVALID_SEQ, out)
            else:
                self._error(cid, HidError.CHANNEL_BUSY, out)
            return
        if length > MAX_PAYLOAD:
            self._error(cid, HidError.INVALID_LEN, out)
            return

        self._channels.move_to_end(cid)
        if length <= INIT_DATA_SIZE:
            self._start(cid, cmd, bytes(data), out)
        else:
            self._active = _Assembling(
                cid, cmd, length, bytearray(data), 0, now + self._assembly_timeout
            )

    def _handle_init(self, cid: int, length: int, data: bytes, out: Output) -> None:
        if length != INIT_NONCE_SIZE:
            self._error(cid, HidError.INVALID_LEN, out)
            return
        if cid == BROADCAST_CID:
            reply_cid = self._allocate_cid()
        elif cid in self._channels:
            reply_cid = cid
            active = self._active
            if active is not None and active.cid == cid:
                if isinstance(active, _Processing):
                    out.cancelled.append(active.txn)
                self._active = None
            self._channels.move_to_end(cid)
        else:
            self._error(cid, HidError.INVALID_CHANNEL, out)
            return
        body = data + struct.pack(
            ">IBBBBB", reply_cid, PROTOCOL_VERSION, *self._device_version, self._capabilities
        )
        out.reports += fragment(cid, Cmd.INIT, body)

    def _handle_cont_packet(self, cid: int, report: bytes, out: Output) -> None:
        active = self._active
        if not isinstance(active, _Assembling) or active.cid != cid:
            return
        if report[4] != active.next_seq:
            self._active = None
            self._error(cid, HidError.INVALID_SEQ, out)
            return
        remaining = active.length - len(active.data)
        active.data += report[5 : 5 + min(remaining, CONT_DATA_SIZE)]
        active.next_seq += 1
        if len(active.data) == active.length:
            self._active = None
            self._start(cid, active.cmd, bytes(active.data), out)

    def _start(self, cid: int, cmd: int, payload: bytes, out: Output) -> None:
        if cmd == Cmd.PING:
            out.reports += fragment(cid, Cmd.PING, payload)
            return
        if cmd not in self._forward:
            self._error(cid, HidError.INVALID_CMD, out)
            return
        self._txn += 1
        self._active = _Processing(self._txn, cid, cmd)
        out.requests.append(Request(self._txn, cid, cmd, payload))

    def _expire(self, now: float, out: Output) -> None:
        active = self._active
        if isinstance(active, _Assembling) and now >= active.deadline:
            self._active = None
            self._error(active.cid, HidError.MSG_TIMEOUT, out)

    def _allocate_cid(self) -> int:
        while True:
            cid = self._cid_source() & 0xFFFFFFFF
            if cid not in (RESERVED_CID, BROADCAST_CID) and cid not in self._channels:
                break
        self._channels[cid] = None
        self._evict_channels()
        return cid

    def _evict_channels(self) -> None:
        # A local client looping on INIT must not grow this table without bound; never evict
        # the channel that owns the current transaction.
        active_cid = self._active.cid if self._active is not None else None
        for cid in list(self._channels):
            if len(self._channels) <= self._max_channels:
                break
            if cid != active_cid:
                del self._channels[cid]

    def _error(self, cid: int, error: int, out: Output) -> None:
        out.reports += fragment(cid, Cmd.ERROR, bytes([error]))
