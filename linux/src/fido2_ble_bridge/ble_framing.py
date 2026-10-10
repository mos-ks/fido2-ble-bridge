"""FIDO BLE frame fragmentation and reassembly (CTAP 2.1, sections 11.4.4 and 11.4.10)."""

from __future__ import annotations

import enum
from dataclasses import dataclass

MIN_FRAGMENT = 20
MAX_FRAGMENT = 512
MAX_FRAME_DATA = 0xFFFF
INIT_HEADER = 3


class BleCmd(enum.IntEnum):
    PING = 0x81
    KEEPALIVE = 0x82
    MSG = 0x83
    CANCEL = 0xBE
    ERROR = 0xBF


class FramingError(Exception):
    """The authenticator sent fragments that do not form a valid frame."""


@dataclass(frozen=True)
class Frame:
    cmd: int
    data: bytes


def fragment_frame(cmd: int, data: bytes, max_len: int) -> list[bytes]:
    if not MIN_FRAGMENT <= max_len <= MAX_FRAGMENT:
        raise ValueError(f"fragment size {max_len} outside {MIN_FRAGMENT}..{MAX_FRAGMENT}")
    if len(data) > MAX_FRAME_DATA:
        raise ValueError(f"frame data of {len(data)} bytes exceeds {MAX_FRAME_DATA}")
    fragments = [bytes([cmd, len(data) >> 8, len(data) & 0xFF]) + data[: max_len - INIT_HEADER]]
    rest = data[max_len - INIT_HEADER :]
    seq = 0
    while rest:
        fragments.append(bytes([seq]) + rest[: max_len - 1])
        rest = rest[max_len - 1 :]
        seq = (seq + 1) & 0x7F
    return fragments


class FrameAssembler:
    """Reassembles notification fragments into frames, rejecting anything out of order."""

    def __init__(self, max_data: int = MAX_FRAME_DATA) -> None:
        self._max_data = max_data
        self._cmd: int | None = None
        self._length = 0
        self._buffer = bytearray()
        self._seq = 0

    def reset(self) -> None:
        self._cmd = None
        self._length = 0
        self._buffer = bytearray()
        self._seq = 0

    def feed(self, fragment: bytes) -> Frame | None:
        if not fragment:
            raise FramingError("empty fragment")
        if fragment[0] & 0x80:
            return self._feed_init(fragment)
        return self._feed_continuation(fragment)

    def _feed_init(self, fragment: bytes) -> Frame | None:
        if self._cmd is not None:
            self.reset()
            raise FramingError("initialization fragment while a frame was incomplete")
        if len(fragment) < INIT_HEADER:
            raise FramingError("initialization fragment shorter than its header")
        cmd = fragment[0]
        length = (fragment[1] << 8) | fragment[2]
        if length > self._max_data:
            raise FramingError(f"frame length {length} exceeds limit {self._max_data}")
        data = fragment[INIT_HEADER:]
        if len(data) >= length:
            # The length field is authoritative; bytes past it are padding.
            return Frame(cmd, bytes(data[:length]))
        self._cmd = cmd
        self._length = length
        self._buffer = bytearray(data)
        self._seq = 0
        return None

    def _feed_continuation(self, fragment: bytes) -> Frame | None:
        if self._cmd is None:
            raise FramingError("continuation fragment without an initialization fragment")
        if fragment[0] != self._seq:
            expected = self._seq
            self.reset()
            raise FramingError(f"continuation sequence {fragment[0]}, expected {expected}")
        self._buffer += fragment[1:]
        self._seq = (self._seq + 1) & 0x7F
        if len(self._buffer) < self._length:
            return None
        frame = Frame(self._cmd, bytes(self._buffer[: self._length]))
        self.reset()
        return frame
