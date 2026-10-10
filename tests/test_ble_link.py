import asyncio

import pytest
from fakes import SimulatedConnector, SoftAuthenticator, assertion_request

from fido2_ble_bridge.ble_link import (
    CTAP2_ERR_KEEPALIVE_CANCEL,
    ErrorResponse,
    FidoBleLink,
    KeyNotReachable,
    KeyNotTrusted,
    KeyUnsupported,
    LinkError,
    MsgResponse,
    Response,
)
from fido2_ble_bridge.ctaphid import MAX_PAYLOAD, HidError

GET_INFO = b"\x04"


async def ask(
    link: FidoBleLink,
    payload: bytes = GET_INFO,
    *,
    connect_timeout: float = 2.0,
    cancelled: asyncio.Event | None = None,
    keepalives: list[int] | None = None,
) -> Response:
    sink = keepalives if keepalives is not None else []
    return await link.request(
        payload,
        connect_timeout=connect_timeout,
        on_keepalive=sink.append,
        cancelled=cancelled or asyncio.Event(),
    )


def make_link(
    connector: SimulatedConnector,
    *,
    idle_disconnect: float = 60.0,
    request_timeout: float = 60.0,
    silence_timeout: float = 0.5,
    cancel_grace: float = 0.3,
) -> FidoBleLink:
    return FidoBleLink(
        connector,
        idle_disconnect=idle_disconnect,
        request_timeout=request_timeout,
        silence_timeout=silence_timeout,
        cancel_grace=cancel_grace,
    )


async def test_handshake_selects_fido2_and_get_info_round_trips() -> None:
    connector = SimulatedConnector()
    link = make_link(connector)
    response = await ask(link)
    assert isinstance(response, MsgResponse)
    assert response.data[0] == 0
    assert connector.last.selected_revision == b"\x20"
    assert link.connected
    await link.close()
    assert not connector.last.connected


async def test_fragment_size_is_bounded_by_mtu_as_well_as_control_point_length() -> None:
    connector = SimulatedConnector(control_point_length=(512).to_bytes(2, "big"), mtu=23)
    link = make_link(connector)
    await ask(link)
    assert link.fragment_size == 20
    assert max(len(w) for w in connector.last.writes) <= 20
    await link.close()


async def test_large_frames_survive_sequence_wraparound_both_ways() -> None:
    payload = bytes(i % 253 for i in range(3000))
    connector = SimulatedConnector(mtu=23, responder=lambda data: data)
    link = make_link(connector)
    response = await ask(link, payload)
    assert response == MsgResponse(payload)
    assert len(connector.last.writes) > 128
    await link.close()


async def test_response_larger_than_ctaphid_can_carry_is_a_link_error() -> None:
    connector = SimulatedConnector(responder=lambda _data: bytes(MAX_PAYLOAD + 1))
    link = make_link(connector)
    with pytest.raises(LinkError):
        await ask(link)
    assert not link.connected


async def test_keepalives_are_relayed_during_user_presence() -> None:
    connector = SimulatedConnector(SoftAuthenticator(user_wait=0.2))
    link = make_link(connector)
    keepalives: list[int] = []
    await ask(link, assertion_request(), keepalives=keepalives)
    assert 2 in keepalives
    await link.close()


@pytest.mark.parametrize(
    ("revision", "error"),
    [(None, KeyUnsupported), (b"\x80", KeyUnsupported), (b"", KeyUnsupported)],
)
async def test_authenticators_without_fido2_over_ble_are_refused(
    revision: bytes | None, error: type[Exception]
) -> None:
    connector = SimulatedConnector(revision=revision)
    with pytest.raises(error):
        await ask(make_link(connector))
    assert not connector.last.connected


@pytest.mark.parametrize("length", [b"\x00\x13", b"\x02\x01", b"\x00", b"\x00\x20\x00"])
async def test_invalid_control_point_length_is_refused(length: bytes) -> None:
    connector = SimulatedConnector(control_point_length=length)
    with pytest.raises(LinkError):
        await ask(make_link(connector))
    assert not connector.last.connected


async def test_unbonded_key_is_refused() -> None:
    with pytest.raises(KeyNotTrusted):
        await ask(make_link(SimulatedConnector(bonded=False)))


async def test_unreachable_key_times_out() -> None:
    link = make_link(SimulatedConnector(reachable=False))
    with pytest.raises(KeyNotReachable):
        await ask(link, connect_timeout=0.2)


async def test_connector_failures_are_reported_as_unreachable() -> None:
    link = make_link(SimulatedConnector(error=OSError("le-connection-abort-by-local")))
    with pytest.raises(KeyNotReachable, match="le-connection-abort"):
        await ask(link)


async def test_ble_error_frame_maps_to_error_response() -> None:
    link = make_link(SimulatedConnector(error_code=b"\x06"))
    assert await ask(link) == ErrorResponse(HidError.CHANNEL_BUSY)
    await link.close()


async def test_unknown_ble_error_code_maps_to_other() -> None:
    link = make_link(SimulatedConnector(error_code=b"\x01\x23"))
    assert await ask(link) == ErrorResponse(HidError.OTHER)
    await link.close()


async def test_silent_authenticator_drops_the_link() -> None:
    connector = SimulatedConnector(silent=True)
    link = make_link(connector)
    with pytest.raises(LinkError, match="stopped responding"):
        await ask(link)
    assert not link.connected
    assert not connector.last.connected


async def test_disconnect_mid_request_fails_fast() -> None:
    link = make_link(SimulatedConnector(disconnect_mid_request=True), silence_timeout=5.0)
    with pytest.raises(LinkError, match="disconnected"):
        async with asyncio.timeout(1.0):
            await ask(link)


async def test_cancel_while_waiting_for_the_user_returns_keepalive_cancel() -> None:
    connector = SimulatedConnector(SoftAuthenticator(user_wait=10.0))
    link = make_link(connector)
    cancelled = asyncio.Event()
    keepalives: list[int] = []

    async def cancel_on_first_keepalive() -> None:
        while not keepalives:
            await asyncio.sleep(0.01)
        cancelled.set()

    canceller = asyncio.create_task(cancel_on_first_keepalive())
    response = await ask(link, assertion_request(), cancelled=cancelled, keepalives=keepalives)
    await canceller
    assert response == MsgResponse(bytes([CTAP2_ERR_KEEPALIVE_CANCEL]))
    assert connector.last.cancels == 1
    await link.close()


async def test_cancel_with_no_reply_is_answered_after_the_grace_period() -> None:
    link = make_link(SimulatedConnector(silent=True), silence_timeout=5.0)
    cancelled = asyncio.Event()
    asyncio.get_running_loop().call_later(0.05, cancelled.set)
    async with asyncio.timeout(2.0):
        response = await ask(link, cancelled=cancelled)
    assert response == MsgResponse(bytes([CTAP2_ERR_KEEPALIVE_CANCEL]))


async def test_cancel_while_connecting_returns_promptly() -> None:
    connector = SimulatedConnector(connect_delay=10.0)
    link = make_link(connector)
    cancelled = asyncio.Event()
    asyncio.get_running_loop().call_later(0.05, cancelled.set)
    async with asyncio.timeout(1.0):
        response = await ask(link, connect_timeout=30.0, cancelled=cancelled)
    assert response == MsgResponse(bytes([CTAP2_ERR_KEEPALIVE_CANCEL]))
    assert not link.connected


async def test_reconnects_after_the_key_powers_down() -> None:
    connector = SimulatedConnector()
    link = make_link(connector)
    await ask(link)
    connector.last.drop()
    assert not link.connected
    assert isinstance(await ask(link), MsgResponse)
    assert connector.connect_calls == 2
    await link.close()


async def test_stale_kept_open_link_is_replaced_transparently() -> None:
    connector = SimulatedConnector()
    link = make_link(connector)
    await ask(link)
    connector.last.connected = False  # died without BlueZ telling us yet
    assert isinstance(await ask(link), MsgResponse)
    assert connector.connect_calls == 2
    await link.close()


async def test_idle_link_is_closed() -> None:
    connector = SimulatedConnector()
    link = make_link(connector, idle_disconnect=0.05)
    await ask(link)
    await asyncio.sleep(0.2)
    assert not link.connected
    assert not connector.last.connected


async def test_requests_are_serialised() -> None:
    connector = SimulatedConnector(SoftAuthenticator(user_wait=0.1))
    link = make_link(connector)
    results = await asyncio.gather(ask(link, assertion_request()), ask(link), ask(link))
    assert all(isinstance(r, MsgResponse) for r in results)
    assert connector.connect_calls == 1
    await link.close()


async def test_notification_flood_fails_the_request_instead_of_losing_frames() -> None:
    connector = SimulatedConnector(keepalive_forever=True, keepalive_interval=0.0)
    link = make_link(connector, silence_timeout=5.0)
    link._events = asyncio.Queue(maxsize=4)
    with pytest.raises(LinkError, match="flooded"):
        async with asyncio.timeout(2.0):
            await ask(link)
    assert not link.connected


async def test_endless_keepalives_hit_the_request_deadline() -> None:
    connector = SimulatedConnector(keepalive_forever=True, keepalive_interval=0.02)
    link = make_link(connector, request_timeout=0.3)
    with pytest.raises(LinkError, match="did not finish"):
        async with asyncio.timeout(3.0):
            await ask(link, connect_timeout=0.5)
    assert not link.connected
    assert not connector.last.connected


async def test_unacknowledged_cancel_retires_the_link() -> None:
    connector = SimulatedConnector(silent=True)
    link = make_link(connector, silence_timeout=5.0)
    cancelled = asyncio.Event()
    asyncio.get_running_loop().call_later(0.05, cancelled.set)
    assert await ask(link, cancelled=cancelled) == MsgResponse(bytes([CTAP2_ERR_KEEPALIVE_CANCEL]))
    assert not link.connected


async def test_stuck_gatt_write_times_out() -> None:
    link = make_link(SimulatedConnector(hang_writes=True), silence_timeout=0.2)
    with pytest.raises(LinkError, match="writing"):
        async with asyncio.timeout(2.0):
            await ask(link)
    assert not link.connected


async def test_garbage_notifications_fail_the_request() -> None:
    connector = SimulatedConnector(silent=True)
    link = make_link(connector, silence_timeout=5.0)

    async def inject() -> None:
        while not connector.sessions or connector.last._notify is None:
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.02)
        assert connector.last._notify is not None
        connector.last._notify(b"\x05garbage")

    injector = asyncio.create_task(inject())
    with pytest.raises(LinkError, match="continuation"):
        async with asyncio.timeout(2.0):
            await ask(link)
    await injector
