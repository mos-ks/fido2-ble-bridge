"""python-fido2's CTAPHID client (an independent implementation) talking to the bridge."""

from __future__ import annotations

import asyncio
import hashlib
import os
import queue
import threading
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass
from typing import Any, TypeVar

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fakes import AAGUID, SimulatedConnector, SoftAuthenticator
from fido2.ctap import CtapError
from fido2.ctap2.base import Ctap2
from fido2.hid import CtapHidDevice
from fido2.hid.base import CtapHidConnection, HidDescriptor
from fido2.webauthn import AuthenticatorData

from fido2_ble_bridge.ble_link import FidoBleLink
from fido2_ble_bridge.bridge import Bridge
from fido2_ble_bridge.ctaphid import PACKET_SIZE

T = TypeVar("T")
RP = {"id": "pam://bridge-test", "name": "bridge test"}
USER = {"id": b"user-id-0123456789", "name": "someone", "displayName": "Some One"}
ES256_PARAMS: list[Mapping[str, Any]] = [{"type": "public-key", "alg": -7}]


class _HidSink:
    def __init__(self) -> None:
        self.inbox: queue.Queue[bytes] = queue.Queue()

    def send_input(self, report: bytes) -> None:
        assert len(report) == PACKET_SIZE
        self.inbox.put(report)


class _Connection(CtapHidConnection):
    def __init__(self, loop: asyncio.AbstractEventLoop, bridge: Bridge, sink: _HidSink) -> None:
        self._loop = loop
        self._bridge = bridge
        self._sink = sink

    def write_packet(self, data: bytes) -> None:
        assert len(data) == PACKET_SIZE
        self._loop.call_soon_threadsafe(self._bridge.on_output_report, bytes(data))

    def read_packet(self) -> bytes:
        return self._sink.inbox.get(timeout=10)

    def close(self) -> None:
        pass


@dataclass
class Rig:
    connector: SimulatedConnector
    link: FidoBleLink
    bridge: Bridge
    sink: _HidSink

    async def device(self) -> CtapHidDevice:
        descriptor = HidDescriptor("loopback", 0, 0, PACKET_SIZE, PACKET_SIZE, None, None)
        connection = _Connection(asyncio.get_running_loop(), self.bridge, self.sink)
        return await asyncio.to_thread(CtapHidDevice, descriptor, connection)

    async def ctap2(self) -> Ctap2:
        return await asyncio.to_thread(Ctap2, await self.device())


async def call(fn: Callable[[], T]) -> T:
    return await asyncio.to_thread(fn)


def make_rig(connector: SimulatedConnector, connect_timeout: float = 2.0) -> Rig:
    link = FidoBleLink(connector, idle_disconnect=60.0, silence_timeout=1.0, cancel_grace=0.5)
    sink = _HidSink()
    return Rig(connector, link, Bridge(sink, link, connect_timeout=connect_timeout), sink)


@pytest.fixture
async def rig() -> AsyncIterator[Rig]:
    rig = make_rig(SimulatedConnector(SoftAuthenticator(user_wait=0.15)))
    yield rig
    await rig.bridge.drain()
    await rig.link.close()


async def test_get_info_reaches_the_authenticator(rig: Rig) -> None:
    ctap = await rig.ctap2()
    assert ctap.info.versions == ["FIDO_2_0"]
    assert ctap.info.aaguid == AAGUID
    assert ctap.info.options["uv"] is True


async def test_ping_is_answered_without_touching_bluetooth(rig: Rig) -> None:
    device = await rig.device()
    payload = os.urandom(300)
    assert await call(lambda: device.ping(payload)) == payload
    assert rig.connector.connect_calls == 0


async def test_registration_and_assertion_verify_end_to_end(rig: Rig) -> None:
    ctap = await rig.ctap2()
    statuses: list[int] = []
    client_data_hash = hashlib.sha256(b"registration").digest()
    attestation = await call(
        lambda: ctap.make_credential(
            client_data_hash,
            RP,
            USER,
            ES256_PARAMS,
            options={"uv": True},
            on_keepalive=statuses.append,
        )
    )
    assert attestation.fmt == "packed"
    credential = attestation.auth_data.credential_data
    assert credential is not None
    assert attestation.auth_data.flags & AuthenticatorData.FLAG.UV
    attestation_key = x509.load_der_x509_certificate(attestation.att_stmt["x5c"][0]).public_key()
    assert isinstance(attestation_key, ec.EllipticCurvePublicKey)
    attestation_key.verify(
        attestation.att_stmt["sig"],
        bytes(attestation.auth_data) + client_data_hash,
        ec.ECDSA(hashes.SHA256()),
    )
    assert 2 in statuses

    challenge = hashlib.sha256(b"login").digest()
    assertion = await call(
        lambda: ctap.get_assertion(
            RP["id"],
            challenge,
            allow_list=[{"type": "public-key", "id": credential.credential_id}],
            options={"uv": True},
        )
    )
    assertion.verify(challenge, credential.public_key)
    assert assertion.auth_data.flags & AuthenticatorData.FLAG.UV


async def test_failed_fingerprint_is_reported_not_masked() -> None:
    rig = make_rig(SimulatedConnector(SoftAuthenticator(uv_succeeds=False, user_wait=0.05)))
    ctap = await rig.ctap2()
    with pytest.raises(CtapError) as raised:
        await call(
            lambda: ctap.make_credential(bytes(32), RP, USER, ES256_PARAMS, options={"uv": True})
        )
    assert raised.value.code == CtapError.ERR.OPERATION_DENIED
    await rig.link.close()


async def test_client_cancel_reaches_the_key(rig: Rig) -> None:
    rig.connector.authenticator.user_wait = 10.0
    ctap = await rig.ctap2()
    cancel = threading.Event()
    with pytest.raises(CtapError) as raised:
        await call(
            lambda: ctap.make_credential(
                bytes(32),
                RP,
                USER,
                ES256_PARAMS,
                event=cancel,
                on_keepalive=lambda status: cancel.set() if status == 2 else None,
            )
        )
    assert raised.value.code == CtapError.ERR.KEEPALIVE_CANCEL
    assert rig.connector.last.cancels == 1


async def test_unreachable_key_fails_with_user_action_timeout() -> None:
    rig = make_rig(SimulatedConnector(reachable=False), connect_timeout=0.3)
    device = await rig.device()
    with pytest.raises(CtapError) as raised:
        await call(lambda: Ctap2(device))
    assert raised.value.code == CtapError.ERR.USER_ACTION_TIMEOUT
    await rig.link.close()


async def test_unbonded_key_fails_closed() -> None:
    rig = make_rig(SimulatedConnector(bonded=False))
    device = await rig.device()
    with pytest.raises(CtapError) as raised:
        await call(lambda: Ctap2(device))
    assert raised.value.code == CtapError.ERR.OTHER
    await rig.link.close()


async def test_u2f_messages_are_refused(rig: Rig) -> None:
    device = await rig.device()
    with pytest.raises(CtapError) as raised:
        await call(lambda: device.call(0x03, bytes.fromhex("00030000")))
    assert raised.value.code == CtapError.ERR.INVALID_COMMAND
    assert rig.connector.connect_calls == 0


async def test_all_handles_closed_cancels_in_flight_work(rig: Rig) -> None:
    rig.connector.authenticator.user_wait = 10.0
    ctap = await rig.ctap2()
    started = threading.Event()
    request = asyncio.create_task(
        call(
            lambda: ctap.make_credential(
                bytes(32), RP, USER, ES256_PARAMS, on_keepalive=lambda _s: started.set()
            )
        )
    )
    await call(lambda: started.wait(5))
    rig.bridge.on_all_closed()
    await asyncio.wait_for(rig.bridge.drain(), 2.0)
    assert rig.connector.last.cancels == 1
    request.cancel()
    rig.sink.inbox.put(b"\0" * PACKET_SIZE)  # unblock the client thread
    await asyncio.gather(request, return_exceptions=True)
