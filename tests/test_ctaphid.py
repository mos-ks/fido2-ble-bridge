import struct
from itertools import count

import pytest

from fido2_ble_bridge.ctaphid import (
    BROADCAST_CID,
    CAPABILITY_CBOR,
    CAPABILITY_NMSG,
    CONT_DATA_SIZE,
    INIT_DATA_SIZE,
    MAX_PAYLOAD,
    PACKET_SIZE,
    Cmd,
    CtapHidServer,
    HidError,
    KeepaliveStatus,
    Output,
    fragment,
)

NONCE = bytes(range(8))


def make_server(**kwargs: object) -> CtapHidServer:
    cids = count(0x1000)
    return CtapHidServer(
        forward=frozenset({Cmd.CBOR}),
        capabilities=CAPABILITY_CBOR | CAPABILITY_NMSG,
        cid_source=lambda: next(cids),
        **kwargs,  # type: ignore[arg-type]
    )


def send(server: CtapHidServer, cid: int, cmd: int, payload: bytes, now: float = 0.0) -> Output:
    out = Output()
    for report in fragment(cid, cmd, payload):
        step = server.handle_report(report, now)
        out.reports += step.reports
        out.requests += step.requests
        out.cancelled += step.cancelled
    return out


def decode(reports: list[bytes]) -> tuple[int, int, bytes]:
    """Reassemble one response message from its reports."""
    cid, cmd, length = struct.unpack_from(">IBH", reports[0])
    data = reports[0][7:]
    for seq, report in enumerate(reports[1:]):
        assert struct.unpack_from(">IB", report) == (cid, seq)
        data += report[5:]
    return cid, cmd, data[:length]


def open_channel(server: CtapHidServer) -> int:
    out = send(server, BROADCAST_CID, Cmd.INIT, NONCE)
    _, _, body = decode(out.reports)
    return int(struct.unpack_from(">I", body, 8)[0])


def assert_error(out: Output, cid: int, error: HidError) -> None:
    assert decode(out.reports) == (cid, Cmd.ERROR, bytes([error]))


def test_fragment_boundaries() -> None:
    assert len(fragment(1, Cmd.CBOR, b"x" * INIT_DATA_SIZE)) == 1
    assert len(fragment(1, Cmd.CBOR, b"x" * (INIT_DATA_SIZE + 1))) == 2
    reports = fragment(1, Cmd.CBOR, b"x" * MAX_PAYLOAD)
    assert len(reports) == 129
    assert struct.unpack_from(">IB", reports[-1]) == (1, 127)
    assert all(len(r) == PACKET_SIZE for r in reports)
    with pytest.raises(ValueError):
        fragment(1, Cmd.CBOR, b"x" * (MAX_PAYLOAD + 1))


def test_init_on_broadcast_allocates_channel_with_spec_layout() -> None:
    server = make_server()
    out = send(server, BROADCAST_CID, Cmd.INIT, NONCE)
    cid, cmd, body = decode(out.reports)
    assert (cid, cmd) == (BROADCAST_CID, Cmd.INIT)
    assert len(body) == 17
    nonce, new_cid, proto, major, minor, build, caps = struct.unpack(">8sIBBBBB", body)
    assert nonce == NONCE
    assert new_cid not in (0, BROADCAST_CID)
    assert proto == 2
    assert caps == CAPABILITY_CBOR | CAPABILITY_NMSG
    assert (major, minor, build) == (0, 1, 0)


def test_init_with_wrong_nonce_length_is_rejected() -> None:
    server = make_server()
    assert_error(
        send(server, BROADCAST_CID, Cmd.INIT, b"short"), BROADCAST_CID, HidError.INVALID_LEN
    )


def test_commands_on_broadcast_or_unknown_channel_are_rejected() -> None:
    server = make_server()
    assert_error(
        send(server, BROADCAST_CID, Cmd.CBOR, b"\x04"), BROADCAST_CID, HidError.INVALID_CHANNEL
    )
    assert_error(send(server, 0xDEAD, Cmd.CBOR, b"\x04"), 0xDEAD, HidError.INVALID_CHANNEL)
    assert_error(send(server, 0xDEAD, Cmd.INIT, NONCE), 0xDEAD, HidError.INVALID_CHANNEL)


def test_ping_is_echoed_locally_across_packets() -> None:
    server = make_server()
    cid = open_channel(server)
    payload = bytes(range(256)) * 2
    out = send(server, cid, Cmd.PING, payload)
    assert decode(out.reports) == (cid, Cmd.PING, payload)
    assert not out.requests
    assert not server.busy


def test_cbor_request_is_reassembled_and_forwarded() -> None:
    server = make_server()
    cid = open_channel(server)
    payload = b"\x02" + bytes(range(200))
    out = send(server, cid, Cmd.CBOR, payload)
    assert not out.reports
    [request] = out.requests
    assert (request.cid, request.cmd, request.payload) == (cid, Cmd.CBOR, payload)
    assert server.busy


def test_response_is_fragmented_and_releases_the_device() -> None:
    server = make_server()
    cid = open_channel(server)
    [request] = send(server, cid, Cmd.CBOR, b"\x04").requests
    response = b"\x00" + bytes(300)
    out = server.respond(request.txn, response)
    assert decode(out.reports) == (cid, Cmd.CBOR, response)
    assert len(out.reports) == 1 + -(-(len(response) - INIT_DATA_SIZE) // CONT_DATA_SIZE)
    assert not server.busy


def test_oversized_response_becomes_an_error() -> None:
    server = make_server()
    cid = open_channel(server)
    [request] = send(server, cid, Cmd.CBOR, b"\x04").requests
    assert_error(server.respond(request.txn, b"x" * (MAX_PAYLOAD + 1)), cid, HidError.OTHER)


def test_other_channel_is_busy_while_a_request_is_processing() -> None:
    server = make_server()
    first, second = open_channel(server), open_channel(server)
    send(server, first, Cmd.CBOR, b"\x04")
    assert_error(send(server, second, Cmd.CBOR, b"\x04"), second, HidError.CHANNEL_BUSY)
    assert_error(send(server, first, Cmd.CBOR, b"\x04"), first, HidError.CHANNEL_BUSY)


def test_init_is_answered_even_while_busy() -> None:
    server = make_server()
    cid = open_channel(server)
    send(server, cid, Cmd.CBOR, b"\x04")
    out = send(server, BROADCAST_CID, Cmd.INIT, NONCE)
    assert decode(out.reports)[1] == Cmd.INIT


def test_bad_sequence_aborts_the_message() -> None:
    server = make_server()
    cid = open_channel(server)
    reports = fragment(cid, Cmd.CBOR, b"x" * 200)
    server.handle_report(reports[0], 0.0)
    out = server.handle_report(reports[2], 0.0)
    assert_error(out, cid, HidError.INVALID_SEQ)
    assert not server.busy


def test_spurious_continuation_is_ignored() -> None:
    server = make_server()
    cid = open_channel(server)
    out = server.handle_report(struct.pack(">IB", cid, 0).ljust(PACKET_SIZE, b"\0"), 0.0)
    assert out == Output()


def test_new_message_on_a_channel_mid_assembly_is_a_sequence_error() -> None:
    server = make_server()
    cid = open_channel(server)
    server.handle_report(fragment(cid, Cmd.CBOR, b"x" * 200)[0], 0.0)
    assert_error(send(server, cid, Cmd.CBOR, b"\x04"), cid, HidError.INVALID_SEQ)


def test_stalled_assembly_times_out_and_frees_the_device() -> None:
    server = make_server(assembly_timeout=1.0)
    first, second = open_channel(server), open_channel(server)
    server.handle_report(fragment(first, Cmd.CBOR, b"x" * 200)[0], 0.0)
    assert_error(server.tick(1.5), first, HidError.MSG_TIMEOUT)
    assert send(server, second, Cmd.CBOR, b"\x04", now=1.6).requests


def test_assembly_expiry_is_also_checked_on_the_next_report() -> None:
    server = make_server(assembly_timeout=1.0)
    first, second = open_channel(server), open_channel(server)
    server.handle_report(fragment(first, Cmd.CBOR, b"x" * 200)[0], 0.0)
    out = send(server, second, Cmd.CBOR, b"\x04", now=2.0)
    assert decode(out.reports) == (first, Cmd.ERROR, bytes([HidError.MSG_TIMEOUT]))
    assert out.requests


def test_cancel_marks_the_active_request_without_replying() -> None:
    server = make_server()
    cid = open_channel(server)
    [request] = send(server, cid, Cmd.CBOR, b"\x02").requests
    out = send(server, cid, Cmd.CANCEL, b"")
    assert out.cancelled == [request.txn]
    assert not out.reports


def test_cancel_from_another_channel_is_ignored() -> None:
    server = make_server()
    first, second = open_channel(server), open_channel(server)
    send(server, first, Cmd.CBOR, b"\x02")
    assert send(server, second, Cmd.CANCEL, b"") == Output()


def test_init_on_own_channel_resyncs_and_drops_the_late_response() -> None:
    server = make_server()
    cid = open_channel(server)
    [request] = send(server, cid, Cmd.CBOR, b"\x02").requests
    out = send(server, cid, Cmd.INIT, NONCE)
    assert out.cancelled == [request.txn]
    assert decode(out.reports)[:2] == (cid, Cmd.INIT)
    assert not server.busy
    assert server.respond(request.txn, b"\x00") == Output()


def test_keepalive_only_for_the_active_request() -> None:
    server = make_server()
    cid = open_channel(server)
    [request] = send(server, cid, Cmd.CBOR, b"\x02").requests
    out = server.keepalive(request.txn, KeepaliveStatus.UPNEEDED)
    assert decode(out.reports) == (cid, Cmd.KEEPALIVE, b"\x02")
    assert server.keepalive(request.txn + 1, KeepaliveStatus.UPNEEDED) == Output()


@pytest.mark.parametrize("cmd", [Cmd.MSG, Cmd.WINK, Cmd.LOCK, 0xC0])
def test_unsupported_commands_are_invalid(cmd: int) -> None:
    server = make_server()
    cid = open_channel(server)
    assert_error(send(server, cid, cmd, b"\x00"), cid, HidError.INVALID_CMD)
    assert not server.busy


def test_declared_length_beyond_maximum_is_invalid() -> None:
    server = make_server()
    cid = open_channel(server)
    report = struct.pack(">IBH", cid, Cmd.CBOR, MAX_PAYLOAD + 1).ljust(PACKET_SIZE, b"\0")
    assert_error(server.handle_report(report, 0.0), cid, HidError.INVALID_LEN)


def test_reports_of_the_wrong_size_are_dropped() -> None:
    server = make_server()
    assert server.handle_report(b"\xff" * 63, 0.0) == Output()
    assert server.handle_report(b"\xff" * 65, 0.0) == Output()


def test_channel_table_is_bounded_and_keeps_the_active_channel() -> None:
    server = make_server(max_channels=4)
    active = open_channel(server)
    send(server, active, Cmd.CBOR, b"\x02")
    for _ in range(20):
        open_channel(server)
    assert len(server._channels) == 4
    assert active in server._channels


def test_abort_all_cancels_and_forgets_channels() -> None:
    server = make_server()
    cid = open_channel(server)
    [request] = send(server, cid, Cmd.CBOR, b"\x02").requests
    assert server.abort_all().cancelled == [request.txn]
    assert not server.busy
    assert_error(send(server, cid, Cmd.CBOR, b"\x04"), cid, HidError.INVALID_CHANNEL)


def test_cancel_is_never_answered_even_on_bad_channels() -> None:
    server = make_server()
    assert send(server, 0xDEADBEEF, Cmd.CANCEL, b"") == Output()
    assert send(server, BROADCAST_CID, Cmd.CANCEL, b"") == Output()
