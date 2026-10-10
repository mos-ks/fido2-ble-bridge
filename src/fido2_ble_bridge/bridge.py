"""Joins the virtual CTAPHID device to the BLE link: one CTAP2 request at a time, forwarded as-is.

The bridge never interprets or creates CTAP2 messages. Whether a login succeeds is decided by
the authenticator's signature, which the client (pam_u2f, a browser) verifies itself.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable
from typing import Protocol

from .ble_link import (
    ErrorResponse,
    KeyNotReachable,
    KeyUnavailable,
    LinkError,
    MsgResponse,
    Response,
)
from .ctaphid import (
    CAPABILITY_CBOR,
    CAPABILITY_NMSG,
    Cmd,
    CtapHidServer,
    HidError,
    KeepaliveStatus,
    Output,
    Request,
)

log = logging.getLogger(__name__)

CTAP2_ERR_USER_ACTION_TIMEOUT = 0x2F
KEEPALIVE_INTERVAL = 0.1


class HidOutput(Protocol):
    def send_input(self, report: bytes) -> None: ...


class AuthenticatorLink(Protocol):
    @property
    def connected(self) -> bool: ...

    async def request(
        self,
        payload: bytes,
        *,
        connect_timeout: float,
        on_keepalive: Callable[[int], None],
        cancelled: asyncio.Event,
    ) -> Response: ...


class Bridge:
    def __init__(
        self,
        hid: HidOutput,
        link: AuthenticatorLink,
        *,
        connect_timeout: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._hid = hid
        self._link = link
        self._connect_timeout = connect_timeout
        self._clock = clock
        # CTAP2 only: pam_u2f, browsers and ssh all speak CBOR to FIDO2 keys, and refusing
        # CTAPHID_MSG keeps U2F's weaker, unverified-user flows off the wire.
        self._server = CtapHidServer(
            forward=frozenset({Cmd.CBOR}), capabilities=CAPABILITY_CBOR | CAPABILITY_NMSG
        )
        self._cancel_events: dict[int, asyncio.Event] = {}
        self._tasks: set[asyncio.Task[None]] = set()

    def on_output_report(self, report: bytes) -> None:
        self._apply(self._server.handle_report(report, self._clock()))

    def on_all_closed(self) -> None:
        self._apply(self._server.abort_all())

    def tick(self) -> None:
        self._apply(self._server.tick(self._clock()))

    async def drain(self) -> None:
        """Wait for in-flight requests to finish (used on shutdown and in tests)."""
        while self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

    def _apply(self, out: Output) -> None:
        for report in out.reports:
            self._hid.send_input(report)
        for txn in out.cancelled:
            event = self._cancel_events.get(txn)
            if event is not None:
                event.set()
        for request in out.requests:
            task = asyncio.create_task(self._forward(request))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _forward(self, request: Request) -> None:
        cancelled = asyncio.Event()
        self._cancel_events[request.txn] = cancelled
        status = [KeepaliveStatus.PROCESSING if self._link.connected else KeepaliveStatus.UPNEEDED]

        def on_keepalive(code: int) -> None:
            status[0] = KeepaliveStatus(code)

        pump = asyncio.create_task(self._keepalive_pump(request.txn, status))
        try:
            response = await self._link.request(
                request.payload,
                connect_timeout=self._connect_timeout,
                on_keepalive=on_keepalive,
                cancelled=cancelled,
            )
        except KeyNotReachable as exc:
            log.info("%s", exc)
            self._apply(self._server.respond(request.txn, bytes([CTAP2_ERR_USER_ACTION_TIMEOUT])))
        except (KeyUnavailable, LinkError) as exc:
            log.warning("request failed: %s", exc)
            self._apply(self._server.fail(request.txn, HidError.OTHER))
        except Exception:
            log.exception("unexpected failure forwarding a request")
            self._apply(self._server.fail(request.txn, HidError.OTHER))
        else:
            self._apply(self._reply(request.txn, response))
        finally:
            pump.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await pump
            self._cancel_events.pop(request.txn, None)

    def _reply(self, txn: int, response: Response) -> Output:
        if isinstance(response, ErrorResponse):
            return self._server.fail(txn, response.code)
        if isinstance(response, MsgResponse) and response.data:
            return self._server.respond(txn, response.data)
        return self._server.fail(txn, HidError.OTHER)

    async def _keepalive_pump(self, txn: int, status: list[KeepaliveStatus]) -> None:
        while True:
            await asyncio.sleep(KEEPALIVE_INTERVAL)
            self._apply(self._server.keepalive(txn, status[0]))
