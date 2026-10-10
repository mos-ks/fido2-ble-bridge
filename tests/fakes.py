"""A software FIDO2 authenticator behind a simulated BLE GATT server.

The simulated key reassembles and fragments BLE frames with its own code rather than
ble_framing, so the bridge's framing is checked against an independent implementation.
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import os
from collections.abc import Callable
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fido2 import cbor
from fido2.cose import ES256
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

from fido2_ble_bridge.ble_link import GattSession, KeyNotReachable, KeyNotTrusted

AAGUID = bytes.fromhex("f1d0b1e0" * 4)

CTAP2_OK = 0x00
CTAP1_ERR_INVALID_COMMAND = 0x01
CTAP2_ERR_MISSING_PARAMETER = 0x14
CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26
CTAP2_ERR_OPERATION_DENIED = 0x27
CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D
CTAP2_ERR_NO_CREDENTIALS = 0x2E

CMD_MAKE_CREDENTIAL = 0x01
CMD_GET_ASSERTION = 0x02
CMD_GET_INFO = 0x04

FLAG = AuthenticatorData.FLAG


def assertion_request(rp_id: str = "example.org", allow: list[bytes] | None = None) -> bytes:
    """A getAssertion that needs the user (up defaults to true)."""
    params: dict[int, Any] = {1: rp_id, 2: bytes(32)}
    if allow:
        params[3] = [{"type": "public-key", "id": cred} for cred in allow]
    return bytes([CMD_GET_ASSERTION]) + cbor.encode(params)


def _attestation_identity() -> tuple[ec.EllipticCurvePrivateKey, bytes]:
    """A batch attestation key and certificate shaped like WebAuthn's packed format wants."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "fido2-ble-bridge tests"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Simulated BLE authenticator"),
        ]
    )
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, certificate.public_bytes(serialization.Encoding.DER)


class SoftAuthenticator:
    """Enough CTAP2 for libfido2, pamu2fcfg and pam_u2f: getInfo, makeCredential, getAssertion.

    `uv_succeeds` stands in for the fingerprint check.
    """

    def __init__(self, *, uv_succeeds: bool = True, user_wait: float = 0.2) -> None:
        self.uv_succeeds = uv_succeeds
        self.user_wait = user_wait
        self.credentials: dict[bytes, tuple[bytes, ec.EllipticCurvePrivateKey]] = {}
        self.counter = 0
        self.commands: list[int] = []
        self.attestation_key, self.attestation_certificate = _attestation_identity()

    def needs_user(self, payload: bytes) -> bool:
        if not payload or payload[0] not in (CMD_MAKE_CREDENTIAL, CMD_GET_ASSERTION):
            return False
        options = self._params(payload).get(7 if payload[0] == CMD_MAKE_CREDENTIAL else 5, {})
        return bool(options.get("up", True) or options.get("uv", False))

    def process(self, payload: bytes) -> bytes:
        self.commands.append(payload[0])
        try:
            return self._process(payload)
        except (KeyError, TypeError, ValueError, AttributeError):
            return bytes([CTAP2_ERR_MISSING_PARAMETER])

    def _process(self, payload: bytes) -> bytes:
        if payload[0] == CMD_GET_INFO:
            info = {
                1: ["FIDO_2_0"],
                3: AAGUID,
                4: {"rk": False, "up": True, "uv": True, "plat": False},
                5: 1200,
                9: ["ble"],
            }
            return bytes([CTAP2_OK]) + cbor.encode(info)
        if payload[0] == CMD_MAKE_CREDENTIAL:
            return self._make_credential(self._params(payload))
        if payload[0] == CMD_GET_ASSERTION:
            return self._get_assertion(self._params(payload))
        return bytes([CTAP1_ERR_INVALID_COMMAND])

    @staticmethod
    def _params(payload: bytes) -> dict[int, Any]:
        decoded = cbor.decode(payload[1:]) if len(payload) > 1 else {}
        assert isinstance(decoded, dict)
        return decoded

    def _make_credential(self, params: dict[int, Any]) -> bytes:
        client_data_hash: bytes = params[1]
        rp_id_hash = hashlib.sha256(params[2]["id"].encode()).digest()
        if not any(p.get("alg") == -7 for p in params[4]):
            return bytes([CTAP2_ERR_UNSUPPORTED_ALGORITHM])
        uv = bool(params.get(7, {}).get("uv", False))
        if uv and not self.uv_succeeds:
            return bytes([CTAP2_ERR_OPERATION_DENIED])
        key = ec.generate_private_key(ec.SECP256R1())
        credential_id = os.urandom(32)
        self.credentials[credential_id] = (rp_id_hash, key)
        flags = FLAG.UP | FLAG.AT | (FLAG.UV if uv else 0)
        auth_data = AuthenticatorData.create(
            rp_id_hash,
            FLAG(flags),
            self.counter,
            AttestedCredentialData.create(
                AAGUID,
                credential_id,
                ES256.from_cryptography_key(key.public_key()),  # type: ignore[no-untyped-call]
            ),
        )
        signature = self.attestation_key.sign(
            bytes(auth_data) + client_data_hash, ec.ECDSA(hashes.SHA256())
        )
        statement = {"alg": -7, "sig": signature, "x5c": [self.attestation_certificate]}
        response = {1: "packed", 2: bytes(auth_data), 3: statement}
        return bytes([CTAP2_OK]) + cbor.encode(response)

    def _get_assertion(self, params: dict[int, Any]) -> bytes:
        rp_id_hash = hashlib.sha256(params[1].encode()).digest()
        client_data_hash: bytes = params[2]
        options = params.get(5, {})
        up = bool(options.get("up", True))
        uv = bool(options.get("uv", False))
        match = next(
            (
                entry["id"]
                for entry in params.get(3, [])
                if entry["id"] in self.credentials
                and self.credentials[entry["id"]][0] == rp_id_hash
            ),
            None,
        )
        if match is None:
            return bytes([CTAP2_ERR_NO_CREDENTIALS])
        if uv and not self.uv_succeeds:
            return bytes([CTAP2_ERR_OPERATION_DENIED])
        self.counter += 1
        flags = (FLAG.UP if up else 0) | (FLAG.UV if uv else 0)
        auth_data = AuthenticatorData.create(rp_id_hash, FLAG(flags), self.counter)
        key = self.credentials[match][1]
        signature = key.sign(bytes(auth_data) + client_data_hash, ec.ECDSA(hashes.SHA256()))
        response = {1: {"type": "public-key", "id": match}, 2: bytes(auth_data), 3: signature}
        return bytes([CTAP2_OK]) + cbor.encode(response)


class SimulatedFidoKey:
    """One GATT connection to a simulated FIDO BLE authenticator (implements GattSession)."""

    def __init__(
        self,
        authenticator: SoftAuthenticator,
        on_disconnect: Callable[[], None],
        *,
        control_point_length: bytes = (128).to_bytes(2, "big"),
        mtu: int = 185,
        revision: bytes | None = b"\x20",
        keepalive_interval: float = 0.05,
        responder: Callable[[bytes], bytes] | None = None,
        error_code: bytes | None = None,
        silent: bool = False,
        disconnect_mid_request: bool = False,
        keepalive_forever: bool = False,
        hang_writes: bool = False,
    ) -> None:
        self.authenticator = authenticator
        self._on_disconnect = on_disconnect
        self.control_point_length = control_point_length
        self.mtu = mtu
        self.revision = revision
        self.keepalive_interval = keepalive_interval
        self.responder = responder
        self.error_code = error_code
        self.silent = silent
        self.disconnect_mid_request = disconnect_mid_request
        self.keepalive_forever = keepalive_forever
        self.hang_writes = hang_writes
        self.connected = True
        self.selected_revision: bytes | None = None
        self.writes: list[bytes] = []
        self.cancels = 0
        self._notify: Callable[[bytes], None] | None = None
        self._rx_cmd: int | None = None
        self._rx_len = 0
        self._rx_seq = 0
        self._rx = bytearray()
        self._task: asyncio.Task[None] | None = None

    @property
    def fragment_limit(self) -> int:
        return self.mtu - 3

    async def read_revision_bitfield(self) -> bytes | None:
        return self.revision

    async def write_revision_bitfield(self, value: bytes) -> None:
        self.selected_revision = value

    async def read_control_point_length(self) -> bytes:
        return self.control_point_length

    async def start_status_notifications(self, callback: Callable[[bytes], None]) -> None:
        self._notify = callback

    async def disconnect(self) -> None:
        self.connected = False
        if self._task is not None:
            self._task.cancel()

    def drop(self) -> None:
        """The key powers down: the link dies and BlueZ reports a disconnect."""
        self.connected = False
        if self._task is not None:
            self._task.cancel()
        self._on_disconnect()

    async def write_control_point(self, fragment: bytes) -> None:
        if not self.connected:
            raise OSError("ATT write on a closed link")
        if self.hang_writes:
            await asyncio.Event().wait()
        limit = min(int.from_bytes(self.control_point_length, "big"), self.fragment_limit)
        assert len(fragment) <= limit, f"fragment of {len(fragment)} bytes exceeds {limit}"
        self.writes.append(fragment)
        if fragment[0] & 0x80:
            assert self._rx_cmd is None, "new frame started before the previous one completed"
            self._rx_cmd = fragment[0]
            self._rx_len = (fragment[1] << 8) | fragment[2]
            self._rx = bytearray(fragment[3:])
            self._rx_seq = 0
        else:
            assert self._rx_cmd is not None, "continuation without initialization"
            assert fragment[0] == self._rx_seq, f"seq {fragment[0]} != expected {self._rx_seq}"
            self._rx += fragment[1:]
            self._rx_seq = (self._rx_seq + 1) % 128
        if self._rx_cmd is not None and len(self._rx) >= self._rx_len:
            cmd, data = self._rx_cmd, bytes(self._rx[: self._rx_len])
            self._rx_cmd = None
            self._dispatch(cmd, data)

    def _dispatch(self, cmd: int, data: bytes) -> None:
        if cmd == 0xBE:
            self.cancels += 1
            if self._task is not None and not self._task.done():
                self._task.cancel()
                self.send_frame(0x83, bytes([CTAP2_ERR_KEEPALIVE_CANCEL]))
            return
        if cmd == 0x81:
            self.send_frame(0x81, data)
            return
        assert cmd == 0x83, f"unexpected command 0x{cmd:02x}"
        self._task = asyncio.create_task(self._process(data))

    async def _process(self, data: bytes) -> None:
        if self.silent:
            return
        if self.keepalive_forever:
            while True:
                self.send_frame(0x82, b"\x01")
                await asyncio.sleep(self.keepalive_interval)
        if self.disconnect_mid_request:
            await asyncio.sleep(0.01)
            self.drop()
            return
        if self.error_code is not None:
            self.send_frame(0xBF, self.error_code)
            return
        if self.responder is not None:
            self.send_frame(0x83, self.responder(data))
            return
        if self.authenticator.needs_user(data):
            waited = 0.0
            while waited < self.authenticator.user_wait:
                self.send_frame(0x82, b"\x02")
                await asyncio.sleep(self.keepalive_interval)
                waited += self.keepalive_interval
        else:
            self.send_frame(0x82, b"\x01")
        self.send_frame(0x83, self.authenticator.process(data))

    def send_frame(self, cmd: int, data: bytes) -> None:
        assert self._notify is not None, "notifications not enabled"
        size = self.fragment_limit
        self._notify(bytes([cmd, len(data) >> 8, len(data) & 0xFF]) + data[: size - 3])
        rest = data[size - 3 :]
        seq = 0
        while rest:
            self._notify(bytes([seq]) + rest[: size - 1])
            rest = rest[size - 1 :]
            seq = (seq + 1) % 128


class SimulatedConnector:
    """GattConnector for a simulated key; each connect() opens a fresh SimulatedFidoKey."""

    def __init__(
        self,
        authenticator: SoftAuthenticator | None = None,
        *,
        reachable: bool = True,
        bonded: bool = True,
        connect_delay: float = 0.0,
        error: Exception | None = None,
        **key_options: Any,
    ) -> None:
        self.authenticator = authenticator or SoftAuthenticator()
        self.reachable = reachable
        self.bonded = bonded
        self.connect_delay = connect_delay
        self.error = error
        self.key_options = key_options
        self.sessions: list[SimulatedFidoKey] = []
        self.failed_connects = 0

    @property
    def connect_calls(self) -> int:
        return len(self.sessions) + self.failed_connects

    async def connect(self, timeout: float, on_disconnect: Callable[[], None]) -> GattSession:
        if not self.reachable:
            self.failed_connects += 1
            await asyncio.sleep(timeout)
            raise KeyNotReachable("simulated key never advertised")
        await asyncio.sleep(self.connect_delay)
        if self.error is not None:
            self.failed_connects += 1
            raise self.error
        if not self.bonded:
            self.failed_connects += 1
            raise KeyNotTrusted("simulated key is not bonded")
        key = SimulatedFidoKey(self.authenticator, on_disconnect, **self.key_options)
        self.sessions.append(key)
        return key

    @property
    def last(self) -> SimulatedFidoKey:
        return self.sessions[-1]
