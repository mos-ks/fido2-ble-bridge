"""CTAP2 requests to a FIDO authenticator over BLE GATT (CTAP 2.1, section 11.4).

The GATT layer sits behind two small protocols so the whole link (handshake, framing,
keepalives, cancel, timeouts, reconnects) runs against a simulated authenticator in tests; only
the bleak adapter in bluez.py needs real hardware.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final, Protocol

from .ble_framing import (
    MAX_FRAGMENT,
    MIN_FRAGMENT,
    BleCmd,
    Frame,
    FrameAssembler,
    FramingError,
    fragment_frame,
)
from .ctaphid import MAX_PAYLOAD, HidError, KeepaliveStatus

log = logging.getLogger(__name__)

FIDO_SERVICE_UUID = "0000fffd-0000-1000-8000-00805f9b34fb"
CONTROL_POINT_UUID = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb"
STATUS_UUID = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb"
CONTROL_POINT_LENGTH_UUID = "f1d0fff3-deaa-ecee-b42f-c9ba7ed623bb"
SERVICE_REVISION_BITFIELD_UUID = "f1d0fff4-deaa-ecee-b42f-c9ba7ed623bb"
REVISION_FIDO2 = 0x20

CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D
# authenticatorGetInfo: changes nothing on the key and needs no user, so it is the one request
# that may be sent twice.
CTAP2_GET_INFO = b"\x04"
PING_NONCE_SIZE = 8


class KeyUnavailable(Exception):
    """The authenticator could not be used for this request."""


class KeyNotReachable(KeyUnavailable):
    """The authenticator did not show up (asleep, out of range) before the timeout."""


class KeyNotTrusted(KeyUnavailable):
    """The device at the configured address is not bonded with this host."""


class KeyUnsupported(KeyUnavailable):
    """The authenticator does not speak FIDO2 over BLE."""


class LinkError(Exception):
    """The BLE link failed while a request was in flight."""


class _WriteFailed(LinkError):
    def __init__(self, message: str, acknowledged: int) -> None:
        super().__init__(message)
        self.acknowledged = acknowledged
        """Fragments the key acknowledged (ATT write responses) before the write failed."""


class GattSession(Protocol):
    async def read_revision_bitfield(self) -> bytes | None: ...
    async def write_revision_bitfield(self, value: bytes) -> None: ...
    async def read_control_point_length(self) -> bytes: ...
    async def write_control_point(self, fragment: bytes) -> None: ...
    async def start_status_notifications(self, callback: Callable[[bytes], None]) -> None: ...
    async def disconnect(self) -> None: ...


class GattConnector(Protocol):
    async def connect(self, timeout: float, on_disconnect: Callable[[], None]) -> GattSession:
        """Find, verify and connect the configured authenticator, or raise KeyUnavailable."""


@dataclass(frozen=True)
class MsgResponse:
    data: bytes


@dataclass(frozen=True)
class ErrorResponse:
    code: int


Response = MsgResponse | ErrorResponse
_Event = Frame | FramingError | LinkError


class _CancelRequested:
    pass


_CANCEL_REQUESTED: Final = _CancelRequested()
_KEEPALIVE_STATUSES = frozenset(int(s) for s in KeepaliveStatus)
_HID_ERRORS = frozenset(int(e) for e in HidError)


def _error_code(data: bytes) -> int:
    code = int.from_bytes(data, "big") if data else HidError.OTHER
    return code if code in _HID_ERRORS else HidError.OTHER


class FidoBleLink:
    def __init__(
        self,
        connector: GattConnector,
        *,
        idle_disconnect: float = 10.0,
        request_timeout: float = 60.0,
        absent_backoff: float = 2.0,
        handshake_timeout: float = 5.0,
        silence_timeout: float = 5.0,
        cancel_grace: float = 3.0,
        disconnect_timeout: float = 5.0,
        ping_after_idle: float = 1.0,
        ping_timeout: float = 1.0,
        queue_limit: int = 256,
    ) -> None:
        self._connector = connector
        self._idle_disconnect = idle_disconnect
        self._request_timeout = request_timeout
        self._absent_backoff = absent_backoff
        self._unreachable_until = 0.0
        self._handshake_timeout = handshake_timeout
        self._silence_timeout = silence_timeout
        self._cancel_grace = cancel_grace
        self._disconnect_timeout = disconnect_timeout
        self._ping_after_idle = ping_after_idle
        self._ping_timeout = ping_timeout
        self._last_traffic = 0.0
        self._session: GattSession | None = None
        self._generation = 0
        self._fragment_size = MIN_FRAGMENT
        self._assembler = FrameAssembler(max_data=MAX_PAYLOAD)
        self._events: asyncio.Queue[_Event] = asyncio.Queue(maxsize=queue_limit)
        self._lock = asyncio.Lock()
        self._idle_task: asyncio.Task[None] | None = None

    @property
    def connected(self) -> bool:
        return self._session is not None

    @property
    def fragment_size(self) -> int:
        return self._fragment_size

    async def request(
        self,
        payload: bytes,
        *,
        connect_timeout: float,
        on_keepalive: Callable[[int], None],
        cancelled: asyncio.Event,
    ) -> Response:
        # A hard deadline on top of the per-step timeouts: an authenticator (or BLE stack) that
        # keeps sending keepalives must not hold a login prompt forever.
        deadline = connect_timeout + self._request_timeout
        async with self._lock:
            self._stop_idle_timer()
            try:
                async with asyncio.timeout(deadline):
                    return await self._request_locked(
                        payload, connect_timeout, on_keepalive, cancelled
                    )
            except TimeoutError as exc:
                await self._drop_session("request deadline exceeded")
                raise LinkError(f"request did not finish within {deadline:g}s") from exc
            finally:
                self._start_idle_timer()

    async def close(self) -> None:
        self._stop_idle_timer()
        async with self._lock:
            await self._drop_session("shutting down")

    async def _request_locked(
        self,
        payload: bytes,
        connect_timeout: float,
        on_keepalive: Callable[[int], None],
        cancelled: asyncio.Event,
    ) -> Response:
        # Authenticators may power down a couple of seconds after a response, so a link kept
        # open for reuse can be dead before its disconnect signal arrives. A request is never
        # simply sent again on a new link, though: the key may have received and acted on it
        # (a PIN change that then fails and burns a PIN retry, a second fingerprint prompt), and
        # a lost ATT write response cannot tell that apart from a dead link.
        cancelled_response = MsgResponse(bytes([CTAP2_ERR_KEEPALIVE_CANCEL]))
        reused = self._session is not None
        session = await self._session_or_cancel(connect_timeout, cancelled)
        if session is None or cancelled.is_set():
            # Cancelled while queued or connecting: the key never sees the request.
            return cancelled_response
        get_info = payload[:1] == CTAP2_GET_INFO
        idle = time.monotonic() - self._last_traffic
        # So anything but getInfo on a kept-open link that sat idle goes only after a PING,
        # which changes nothing on the key, proved the link alive.
        if (
            reused
            and not get_info
            and idle > self._ping_after_idle
            and not await self._ping(session)
        ):
            log.info("kept-open BLE link did not answer a PING, reconnecting")
            reused = False
            session = await self._session_or_cancel(connect_timeout, cancelled)
            if session is None:
                return cancelled_response
        if cancelled.is_set():
            # Cancelled during the PING or the reconnect: the key never sees the request.
            return cancelled_response
        try:
            await self._send(session, payload)
        except _WriteFailed as exc:
            # getInfo alone may go again, and only when the key acknowledged none of it on a
            # kept-open link: the stale-link case, where repeating it costs nothing.
            if not (reused and get_info and exc.acknowledged == 0):
                raise
            if cancelled.is_set():
                return cancelled_response
            log.info("kept-open BLE link was stale, reconnecting")
            session = await self._session_or_cancel(connect_timeout, cancelled)
            if session is None or cancelled.is_set():
                return cancelled_response
            await self._send(session, payload)
        return await self._receive(session, on_keepalive, cancelled)

    async def _ping(self, session: GattSession) -> bool:
        """Whether the key echoes a PING with a fresh random payload within ping_timeout (a stray
        or late echo cannot pass for it). Drops the link if not."""
        nonce = secrets.token_bytes(PING_NONCE_SIZE)
        try:
            await self._send(session, nonce, BleCmd.PING)
        except LinkError:
            return False
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._ping_timeout
        while True:
            event = await self._next_event(None, max(0.0, deadline - loop.time()))
            if not isinstance(event, Frame) or event.cmd not in (BleCmd.PING, BleCmd.KEEPALIVE):
                break
            if event.cmd == BleCmd.PING:
                if event.data == nonce:
                    return True
                break
        await self._drop_session("no answer to PING")
        return False

    async def _session_or_cancel(
        self, timeout: float, cancelled: asyncio.Event
    ) -> GattSession | None:
        if self._session is not None:
            return self._session
        loop = asyncio.get_running_loop()
        if loop.time() < self._unreachable_until:
            # pam_u2f reopens the device once per registered credential; with the key away,
            # each reopen would otherwise wait the full connect timeout again.
            raise KeyNotReachable("authenticator was unreachable moments ago")
        opener = asyncio.create_task(self._open(timeout))
        canceller = asyncio.create_task(cancelled.wait())
        try:
            done, _ = await asyncio.wait({opener, canceller}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            canceller.cancel()
            if not opener.done():
                opener.cancel()
        if opener in done:
            try:
                return opener.result()
            except KeyNotReachable:
                self._unreachable_until = loop.time() + self._absent_backoff
                raise
        await asyncio.wait({opener})
        if not opener.cancelled() and opener.exception() is not None:
            log.debug("connect abandoned after cancel: %r", opener.exception())
        return None

    async def _open(self, timeout: float) -> GattSession:
        self._generation += 1
        generation = self._generation
        try:
            async with asyncio.timeout(timeout):
                session = await self._connector.connect(
                    timeout, lambda: self._on_disconnect(generation)
                )
        except KeyUnavailable:
            raise
        except TimeoutError as exc:
            raise KeyNotReachable(f"authenticator not reachable within {timeout:g}s") from exc
        except Exception as exc:
            raise KeyNotReachable(f"connecting to the authenticator failed: {exc}") from exc
        try:
            async with asyncio.timeout(self._handshake_timeout):
                await self._handshake(session, generation)
        except BaseException as exc:
            await self._disconnect_quietly(session)
            if isinstance(exc, KeyUnavailable | LinkError) or not isinstance(exc, Exception):
                raise
            raise LinkError(f"FIDO service handshake failed: {exc!r}") from exc
        self._session = session
        self._last_traffic = time.monotonic()
        return session

    async def _handshake(self, session: GattSession, generation: int) -> None:
        bitfield = await session.read_revision_bitfield()
        if not bitfield or not bitfield[0] & REVISION_FIDO2:
            raise KeyUnsupported("authenticator does not offer FIDO2 over BLE")
        await session.write_revision_bitfield(bytes([REVISION_FIDO2]))
        raw = await session.read_control_point_length()
        if len(raw) != 2:
            raise LinkError(f"fidoControlPointLength is {len(raw)} bytes, expected 2")
        control_point_length = int.from_bytes(raw, "big")
        if not MIN_FRAGMENT <= control_point_length <= MAX_FRAGMENT:
            raise LinkError(f"fidoControlPointLength {control_point_length} out of range")
        # Fragments as long as the key allows, never shorter: some keys (Feitian AllinPass K33)
        # refuse a message whose fragments are shorter than fidoControlPointLength, and on BlueZ
        # the write limit bleak reports is often the 20-byte default rather than the real MTU.
        # Fragments go out as ATT write requests, which BlueZ turns into a long write if needed.
        self._fragment_size = control_point_length
        self._assembler.reset()
        self._drain()
        await session.start_status_notifications(
            lambda data: self._on_notification(generation, data)
        )
        log.info("BLE link ready, fragment size %d", self._fragment_size)

    async def _send(self, session: GattSession, payload: bytes, cmd: BleCmd = BleCmd.MSG) -> None:
        self._drain()
        self._assembler.reset()
        acknowledged = 0
        try:
            for piece in fragment_frame(cmd, payload, self._fragment_size):
                async with asyncio.timeout(self._silence_timeout):
                    await session.write_control_point(piece)
                acknowledged += 1
                self._last_traffic = time.monotonic()
        except Exception as exc:
            await self._drop_session("write failed")
            raise _WriteFailed(
                f"writing to the authenticator failed: {exc!r}", acknowledged
            ) from exc

    async def _receive(
        self,
        session: GattSession,
        on_keepalive: Callable[[int], None],
        cancelled: asyncio.Event,
    ) -> Response:
        loop = asyncio.get_running_loop()
        cancel_deadline: float | None = None
        while True:
            if cancel_deadline is None:
                event = await self._next_event(cancelled, self._silence_timeout)
            else:
                # Absolute: keepalives after a CANCEL must not extend the wait.
                event = await self._next_event(None, max(0.0, cancel_deadline - loop.time()))
            if isinstance(event, _CancelRequested):
                await self._send_cancel(session)
                cancel_deadline = loop.time() + self._cancel_grace
                continue
            if event is None:
                if cancel_deadline is not None:
                    # BLE frames carry no request ID: a reply arriving later would be read as
                    # the answer to the next request, so this link cannot be reused.
                    await self._drop_session("cancel not acknowledged")
                    return MsgResponse(bytes([CTAP2_ERR_KEEPALIVE_CANCEL]))
                await self._drop_session("authenticator went silent")
                raise LinkError("authenticator stopped responding")
            if isinstance(event, FramingError | LinkError):
                await self._drop_session(str(event))
                raise LinkError(str(event)) from event
            if event.cmd == BleCmd.KEEPALIVE:
                if len(event.data) == 1 and event.data[0] in _KEEPALIVE_STATUSES:
                    on_keepalive(event.data[0])
                continue
            if event.cmd == BleCmd.MSG:
                return MsgResponse(event.data)
            if event.cmd == BleCmd.ERROR:
                return ErrorResponse(_error_code(event.data))
            await self._drop_session("unexpected frame")
            raise LinkError(f"unexpected frame command 0x{event.cmd:02x}")

    async def _next_event(
        self, cancelled: asyncio.Event | None, timeout: float
    ) -> _Event | _CancelRequested | None:
        if cancelled is not None and cancelled.is_set():
            return _CANCEL_REQUESTED
        getter = asyncio.create_task(self._events.get())
        waiters: set[asyncio.Task[Any]] = {getter}
        canceller = None
        if cancelled is not None:
            canceller = asyncio.create_task(cancelled.wait())
            waiters.add(canceller)
        try:
            done, _ = await asyncio.wait(
                waiters, timeout=timeout, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            for waiter in waiters:
                if not waiter.done():
                    waiter.cancel()
        if getter in done:
            return getter.result()
        if canceller is not None and canceller in done:
            return _CANCEL_REQUESTED
        return None

    async def _send_cancel(self, session: GattSession) -> None:
        try:
            async with asyncio.timeout(self._silence_timeout):
                await session.write_control_point(
                    fragment_frame(BleCmd.CANCEL, b"", self._fragment_size)[0]
                )
        except Exception as exc:
            log.warning("sending CANCEL to the authenticator failed: %r", exc)

    def _on_notification(self, generation: int, data: bytes) -> None:
        if generation != self._generation:
            return
        self._last_traffic = time.monotonic()
        try:
            frame = self._assembler.feed(data)
        except FramingError as exc:
            self._post(exc)
            return
        if frame is not None:
            self._post(frame)

    def _on_disconnect(self, generation: int) -> None:
        if generation != self._generation:
            return
        log.info("authenticator disconnected")
        self._session = None
        self._assembler.reset()
        self._post(LinkError("authenticator disconnected"))

    def _post(self, event: _Event) -> None:
        try:
            self._events.put_nowait(event)
        except asyncio.QueueFull:
            # Dropping one event could lose the final response; fail the request instead.
            self._drain()
            self._events.put_nowait(LinkError("authenticator flooded the link with notifications"))

    def _drain(self) -> None:
        while not self._events.empty():
            self._events.get_nowait()

    async def _drop_session(self, reason: str) -> None:
        session, self._session = self._session, None
        self._generation += 1
        self._assembler.reset()
        if session is None:
            return
        log.info("closing BLE link: %s", reason)
        await self._disconnect_quietly(session)

    async def _disconnect_quietly(self, session: GattSession) -> None:
        # Bounded: a disconnect that hangs in the Bluetooth stack must not hold a login prompt.
        with contextlib.suppress(Exception):
            async with asyncio.timeout(self._disconnect_timeout):
                await session.disconnect()

    def _start_idle_timer(self) -> None:
        if self._session is not None and self._idle_task is None:
            self._idle_task = asyncio.create_task(self._disconnect_when_idle())

    def _stop_idle_timer(self) -> None:
        if self._idle_task is not None:
            self._idle_task.cancel()
            self._idle_task = None

    async def _disconnect_when_idle(self) -> None:
        await asyncio.sleep(self._idle_disconnect)
        async with self._lock:
            self._idle_task = None
            await self._drop_session("idle")
