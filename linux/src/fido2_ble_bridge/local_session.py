"""`pam_exec` helper of the PAM profile: does this login request come from a person at this
computer? Exit status 0 means yes, and pam_u2f may ask the key. Anything else (another exit
status, a crash, a missing helper) makes the profile skip the key, so PAM asks for the password.

The profile runs it for sudo, sudo -i and the console's login:

    [success=ignore default=2]  pam_exec.so quiet /opt/fido2-ble-bridge/bin/python -I -m ...

pam_exec starts it as a child of the program that asks (sudo, login), so it sits in that
program's cgroup and with that in its logind session. It reads logind's state through
libsystemd's sd-login API (files under /run/systemd: no D-Bus, nothing that can hang) and fails
closed: whatever it cannot establish counts as "not local".

The rules, for the account PAM authenticates (PAM_USER):

1. PAM_RHOST names another host: not local.
2. The caller is in a login session: local only if that session belongs to PAM_USER, is not
   remote, and sits at a seat. SSH sessions are remote; xrdp, containers and the like have no
   seat. So `sudo` over SSH, and `su`, `pkexec` and the like from someone else's session, are
   refused.
3. The caller is in no login session (the seatless session systemd 256 and newer give a user's
   service manager counts as none):
   a. `login`, which getty starts before any session exists: local only on a virtual console
      (PAM_TTY ttyN) and without PAM_RHOST.
   b. A process of PAM_USER's own systemd user instance, where GNOME and KDE start terminals,
      outside the login session: local only if the user's graphical session passes rule 2 and
      is active, and none of the user's login sessions is remote or seatless. Polkit uses the
      graphical session for such processes too; the second condition is extra.
   c. Anything else (a system service, cron, ...): not local.
"""

from __future__ import annotations

import ctypes
import errno
import os
import pwd
import re
import signal
import socket
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

TIME_LIMIT = 5  # seconds; sd-login only reads files, so this is a backstop
_VIRTUAL_CONSOLE = re.compile(r"(/dev/)?tty[0-9]+")
_LOCAL_HOSTS = frozenset({"", "localhost", "127.0.0.1", "::1"})
_SELF = 0  # sd-login's "the calling process"


class LoginStateError(Exception):
    """logind's state could not be read; the key is skipped."""


class Logind(Protocol):
    """The parts of sd-login the rules need. Every method raises LoginStateError on errors."""

    def session_of(self, pid: int) -> str | None:
        """The logind session of process `pid` (0: this one), None if it is in none."""

    def owner_uid_of(self, pid: int) -> int | None:
        """The user whose service manager or session owns process `pid`, None if no user's."""

    def session_uid(self, session: str) -> int: ...
    def session_class(self, session: str) -> str: ...
    def is_remote(self, session: str) -> bool: ...
    def is_active(self, session: str) -> bool: ...
    def seat(self, session: str) -> str | None: ...

    def display(self, uid: int) -> str | None:
        """The user's graphical ("display") session, None if there is none."""

    def sessions(self, uid: int) -> list[str]: ...


@dataclass(frozen=True)
class Request:
    """What pam_exec passes on about the authentication (PAM_SERVICE, PAM_TTY, PAM_RHOST)."""

    service: str
    uid: int
    """The uid of PAM_USER, the account being authenticated."""
    tty: str = ""
    rhost: str = ""


@dataclass(frozen=True)
class Verdict:
    local: bool
    reason: str


def _seated_and_local(login: Logind, session: str) -> str | None:
    """Why `session` is not one at this computer's seat, or None if it is."""
    if login.is_remote(session):
        return f"session {session} is remote"
    if login.seat(session) is None:
        return f"session {session} has no seat"
    return None


def _own_local_session(login: Logind, session: str, uid: int) -> Verdict:
    if login.session_uid(session) != uid:
        return Verdict(False, f"session {session} belongs to another account")
    if (why := _seated_and_local(login, session)) is not None:
        return Verdict(False, why)
    return Verdict(True, f"local session {session}")


def decide(request: Request, login: Logind, local_names: frozenset[str] = _LOCAL_HOSTS) -> Verdict:
    """Whether the request comes from a person at this computer; see the module docstring."""
    if request.rhost not in local_names:
        return Verdict(False, f"remote host {request.rhost!r}")
    session = login.session_of(_SELF)
    if session is not None and not login.session_class(session).startswith("manager"):
        return _own_local_session(login, session, request.uid)
    if request.service == "login":
        if _VIRTUAL_CONSOLE.fullmatch(request.tty) and not request.rhost:
            return Verdict(True, f"console login on {request.tty}")
        return Verdict(False, f"login on {request.tty or 'no terminal'}, not a virtual console")
    if login.owner_uid_of(_SELF) != request.uid:
        return Verdict(False, "not in a login session or the user's own service manager")
    display = login.display(request.uid)
    if display is None:
        return Verdict(False, "no login session, and no graphical session to go by")
    verdict = _own_local_session(login, display, request.uid)
    if not verdict.local:
        return verdict
    if not login.is_active(display):
        return Verdict(False, f"graphical session {display} is not active")
    for other in login.sessions(request.uid):
        # Login sessions only: since systemd 256 the service manager has a seatless session of
        # its own (class "manager"), and background sessions are not someone logging in.
        if not login.session_class(other).startswith("user"):
            continue
        if (why := _seated_and_local(login, other)) is not None:
            return Verdict(False, why)
    return Verdict(True, f"user service manager, graphical session {display}")


class SdLogin:
    """Logind through libsystemd's sd-login functions (stable C API, see sd-login(3))."""

    def __init__(self, library: str = "libsystemd.so.0") -> None:
        try:
            self._lib = ctypes.CDLL(library, use_errno=True)
        except OSError as exc:
            raise LoginStateError(f"cannot load {library}: {exc}") from exc
        self._free = ctypes.CDLL(None).free
        self._free.argtypes = [ctypes.c_void_p]
        self._free.restype = None
        string = ctypes.POINTER(ctypes.c_void_p)
        uid = ctypes.POINTER(ctypes.c_uint32)
        name = ctypes.c_char_p
        self._declare("sd_pid_get_session", ctypes.c_int, string)
        self._declare("sd_pid_get_owner_uid", ctypes.c_int, uid)
        self._declare("sd_session_get_uid", name, uid)
        self._declare("sd_session_get_class", name, string)
        self._declare("sd_session_get_seat", name, string)
        self._declare("sd_session_is_remote", name)
        self._declare("sd_session_is_active", name)
        self._declare("sd_uid_get_display", ctypes.c_uint32, string)
        self._declare("sd_uid_get_sessions", ctypes.c_uint32, ctypes.c_int, ctypes.POINTER(string))

    def _declare(self, function: str, *argtypes: Any) -> None:
        try:
            symbol = getattr(self._lib, function)
        except AttributeError as exc:
            raise LoginStateError(f"libsystemd has no {function}") from exc
        symbol.argtypes = list(argtypes)
        symbol.restype = ctypes.c_int

    def _call(self, function: str, *args: Any, missing: tuple[int, ...] = ()) -> int | None:
        """The function's non-negative result; None for the "no such thing" errors in
        `missing`; LoginStateError for any other error."""
        result = int(getattr(self._lib, function)(*args))
        if result >= 0:
            return result
        if -result in missing:
            return None
        raise LoginStateError(f"{function}: {os.strerror(-result)}")

    def _string(self, function: str, *args: Any, missing: tuple[int, ...] = ()) -> str | None:
        out = ctypes.c_void_p()
        if self._call(function, *args, ctypes.byref(out), missing=missing) is None:
            return None
        try:
            return ctypes.string_at(out.value).decode() if out.value else None
        finally:
            self._free(out)

    def _uid(self, function: str, *args: Any, missing: tuple[int, ...] = ()) -> int | None:
        out = ctypes.c_uint32()
        if self._call(function, *args, ctypes.byref(out), missing=missing) is None:
            return None
        return int(out.value)

    @staticmethod
    def _name(session: str) -> bytes:
        return session.encode()

    def session_of(self, pid: int) -> str | None:
        return self._string("sd_pid_get_session", pid, missing=(errno.ENODATA, errno.ENXIO))

    def owner_uid_of(self, pid: int) -> int | None:
        return self._uid("sd_pid_get_owner_uid", pid, missing=(errno.ENODATA, errno.ENXIO))

    def session_uid(self, session: str) -> int:
        uid = self._uid("sd_session_get_uid", self._name(session))
        if uid is None:  # cannot happen: no error is listed as `missing`
            raise LoginStateError(f"no uid for session {session}")
        return uid

    def session_class(self, session: str) -> str:
        return self._string("sd_session_get_class", self._name(session)) or ""

    def is_remote(self, session: str) -> bool:
        return bool(self._call("sd_session_is_remote", self._name(session)))

    def is_active(self, session: str) -> bool:
        return bool(self._call("sd_session_is_active", self._name(session)))

    def seat(self, session: str) -> str | None:
        return self._string("sd_session_get_seat", self._name(session), missing=(errno.ENODATA,))

    def display(self, uid: int) -> str | None:
        return self._string("sd_uid_get_display", uid, missing=(errno.ENODATA, errno.ENXIO))

    def sessions(self, uid: int) -> list[str]:
        array = ctypes.POINTER(ctypes.c_void_p)()
        count = self._call("sd_uid_get_sessions", uid, 0, ctypes.byref(array))
        if not array:
            return []
        names: list[str] = []
        try:
            for index in range(count or 0):
                pointer = array[index]
                if pointer:
                    names.append(ctypes.string_at(pointer).decode())
        finally:
            for index in range(count or 0):
                self._free(array[index])
            self._free(array)
        return names


def main(
    environ: Mapping[str, str] | None = None,
    logind: Callable[[], Logind] = SdLogin,
) -> int:
    signal.alarm(TIME_LIMIT)  # SIGALRM ends the process: pam_exec sees a failure
    env = os.environ if environ is None else environ
    try:
        request = Request(
            service=env.get("PAM_SERVICE", ""),
            uid=pwd.getpwnam(env["PAM_USER"]).pw_uid,
            tty=env.get("PAM_TTY", ""),
            rhost=env.get("PAM_RHOST", ""),
        )
        verdict = decide(request, logind(), _LOCAL_HOSTS | {socket.gethostname()})
    except Exception as exc:  # fail closed: no key without a clear "local"
        verdict = Verdict(False, f"cannot tell ({exc!r})")
    finally:
        signal.alarm(0)
    # pam_exec sends this to /dev/null unless its log= option is set.
    outcome = "using the key" if verdict.local else "not using the key"
    print(f"fido2-ble-bridge: {outcome}: {verdict.reason}", file=sys.stderr)
    return 0 if verdict.local else 1


if __name__ == "__main__":
    sys.exit(main())
