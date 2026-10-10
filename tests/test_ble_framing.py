import pytest

from fido2_ble_bridge.ble_framing import (
    BleCmd,
    Frame,
    FrameAssembler,
    FramingError,
    fragment_frame,
)


def test_spec_example_ping_40_bytes_at_max_len_20() -> None:
    data = bytes(range(40))
    fragments = fragment_frame(BleCmd.PING, data, 20)
    assert fragments == [
        bytes.fromhex("810028") + data[:17],
        b"\x00" + data[17:36],
        b"\x01" + data[36:],
    ]


def test_spec_example_ping_400_bytes_at_max_len_512() -> None:
    data = bytes(400)
    assert fragment_frame(BleCmd.PING, data, 512) == [bytes.fromhex("810190") + data]


def test_empty_frame_is_a_header_only_fragment() -> None:
    assert fragment_frame(BleCmd.CANCEL, b"", 20) == [b"\xbe\x00\x00"]


def test_sequence_wraps_after_0x7f() -> None:
    data = bytes(17 + 19 * 130)
    fragments = fragment_frame(BleCmd.MSG, data, 20)
    sequences = [f[0] for f in fragments[1:]]
    assert sequences[:128] == list(range(128))
    assert sequences[128:] == [0, 1]


@pytest.mark.parametrize("max_len", [19, 513])
def test_fragment_size_must_be_within_spec_range(max_len: int) -> None:
    with pytest.raises(ValueError):
        fragment_frame(BleCmd.MSG, b"x", max_len)


def test_assembler_round_trips_with_sequence_wrap() -> None:
    data = bytes(i % 251 for i in range(5000))
    assembler = FrameAssembler()
    fragments = fragment_frame(BleCmd.MSG, data, 20)
    results = [assembler.feed(f) for f in fragments]
    assert results[:-1] == [None] * (len(fragments) - 1)
    assert results[-1] == Frame(BleCmd.MSG, data)


def test_assembler_ignores_padding_after_declared_length() -> None:
    assembler = FrameAssembler()
    assert assembler.feed(bytes.fromhex("820001") + b"\x02\x00\x00") == Frame(0x82, b"\x02")


def test_continuation_without_initialization_is_rejected() -> None:
    with pytest.raises(FramingError):
        FrameAssembler().feed(b"\x00abc")


def test_out_of_order_continuation_is_rejected_and_resets() -> None:
    assembler = FrameAssembler()
    fragments = fragment_frame(BleCmd.MSG, bytes(100), 20)
    assembler.feed(fragments[0])
    with pytest.raises(FramingError):
        assembler.feed(fragments[2])
    assert assembler.feed(fragment_frame(BleCmd.MSG, b"ok", 20)[0]) == Frame(BleCmd.MSG, b"ok")


def test_new_initialization_while_incomplete_is_rejected() -> None:
    assembler = FrameAssembler()
    assembler.feed(fragment_frame(BleCmd.MSG, bytes(100), 20)[0])
    with pytest.raises(FramingError):
        assembler.feed(bytes.fromhex("820001") + b"\x01")


def test_declared_length_above_limit_is_rejected() -> None:
    with pytest.raises(FramingError):
        FrameAssembler(max_data=100).feed(bytes.fromhex("830065"))


@pytest.mark.parametrize("fragment", [b"", b"\x83\x00"])
def test_malformed_initialization_is_rejected(fragment: bytes) -> None:
    with pytest.raises(FramingError):
        FrameAssembler().feed(fragment)
