"""The PAM profile's local-session check (pam_exec helper): who gets the key, and failing closed."""

from __future__ import annotations

import ctypes.util
import os
import signal
import subprocess
import sys
from dataclasses import dataclass, field

import pytest

from fido2_ble_bridge.local_session import (
    LoginStateError,
    Request,
    SdLogin,
    Verdict,
    decide,
    main,
)

OWNER = 1000
OTHER = 1001


@dataclass
class Session:
    uid: int = OWNER
    remote: bool = False
    seat: str | None = "seat0"
    active: bool = True
    kind: str = "user"


@dataclass
class FakeLogind:
    """logind as sd-login reports it: the caller's session or owner, and the sessions."""

    caller_session: str | None = None
    caller_owner: int | None = None
    sessions_by_id: dict[str, Session] = field(default_factory=dict)
    displays: dict[int, str] = field(default_factory=dict)
    broken: bool = False

    def _check(self) -> None:
        if self.broken:
            raise LoginStateError("sd_pid_get_session: Input/output error")

    def session_of(self, pid: int) -> str | None:
        assert pid == 0, "the check asks about its own process, the PAM program's child"
        self._check()
        return self.caller_session

    def owner_uid_of(self, pid: int) -> int | None:
        assert pid == 0
        self._check()
        return self.caller_owner

    def session_uid(self, session: str) -> int:
        return self.sessions_by_id[session].uid

    def session_class(self, session: str) -> str:
        return self.sessions_by_id[session].kind

    def is_remote(self, session: str) -> bool:
        return self.sessions_by_id[session].remote

    def is_active(self, session: str) -> bool:
        return self.sessions_by_id[session].active

    def seat(self, session: str) -> str | None:
        return self.sessions_by_id[session].seat

    def display(self, uid: int) -> str | None:
        return self.displays.get(uid)

    def sessions(self, uid: int) -> list[str]:
        return [name for name, session in self.sessions_by_id.items() if session.uid == uid]


def sudo(uid: int = OWNER, **fields: str) -> Request:
    return Request(service="sudo", uid=uid, tty="/dev/pts/3", **fields)


def in_session(session: Session, **extra: Session) -> FakeLogind:
    return FakeLogind(caller_session="2", sessions_by_id={"2": session, **extra})


def desktop_terminal(**sessions: Session) -> FakeLogind:
    """sudo in a terminal GNOME or KDE started through the user's systemd instance."""
    return FakeLogind(
        caller_owner=OWNER,
        sessions_by_id={"2": Session(), **sessions},
        displays={OWNER: "2"},
    )


# Rule 2: the caller is in a login session.


def test_sudo_in_your_own_session_at_this_computer_uses_the_key() -> None:
    assert decide(sudo(), in_session(Session())).local


@pytest.mark.parametrize(
    ("session", "why"),
    [
        (Session(remote=True, seat=None), "remote"),  # ssh
        (Session(seat=None), "no seat"),  # xrdp, a container, machinectl shell
        (Session(uid=OTHER), "another account"),  # su yourname / pkexec from someone else
    ],
)
def test_sessions_that_are_not_yours_at_this_computer_skip_the_key(
    session: Session, why: str
) -> None:
    verdict = decide(sudo(), in_session(session))
    assert not verdict.local
    assert why in verdict.reason


def test_a_remote_host_skips_the_key_whatever_the_session() -> None:
    verdict = decide(sudo(rhost="attacker.example"), in_session(Session()))
    assert verdict == Verdict(False, "remote host 'attacker.example'")


def test_sudo_s_own_host_name_as_rhost_is_not_remote() -> None:
    # sudo's pam_rhost option sets PAM_RHOST to the local host's name.
    names = frozenset({"", "localhost", "laptop"})
    assert decide(sudo(rhost="laptop"), in_session(Session()), names).local


# Rule 3a: login, before any session exists.


@pytest.mark.parametrize(("tty", "rhost", "local"), [
    ("tty1", "", True),
    ("/dev/tty3", "", True),
    ("pts/0", "", False),  # telnet and the like
    ("tty1", "attacker.example", False),
    ("ttyS0", "", False),
    ("", "", False),
])  # fmt: skip
def test_login_uses_the_key_only_on_a_virtual_console(tty: str, rhost: str, local: bool) -> None:
    request = Request(service="login", uid=OWNER, tty=tty, rhost=rhost)
    assert decide(request, FakeLogind()).local is local


# Rule 3b: a process of the user's own service manager (GNOME and KDE terminals).


def test_a_desktop_terminal_goes_by_the_local_graphical_session() -> None:
    assert decide(sudo(), desktop_terminal()).local


def test_the_service_manager_s_own_session_counts_as_no_session() -> None:
    # systemd 256 and newer: a seatless "manager" session for user@.service.
    login = desktop_terminal(m=Session(seat=None, kind="manager"))
    login.caller_session = "m"
    assert decide(sudo(), login).local


@pytest.mark.parametrize(
    ("login", "why"),
    [
        (desktop_terminal(ssh=Session(remote=True, seat=None)), "remote"),
        (desktop_terminal(rdp=Session(seat=None)), "no seat"),
        (FakeLogind(caller_owner=OWNER, sessions_by_id={"2": Session()}), "no graphical"),
        (
            FakeLogind(
                caller_owner=OWNER,
                sessions_by_id={"2": Session(active=False)},
                displays={OWNER: "2"},
            ),
            "not active",
        ),
        (
            FakeLogind(
                caller_owner=OWNER,
                sessions_by_id={"2": Session(remote=True, seat=None)},
                displays={OWNER: "2"},
            ),
            "remote",
        ),
        (FakeLogind(caller_owner=OTHER, displays={OWNER: "2"}), "not in a login session"),
        (FakeLogind(), "not in a login session"),  # a system service, cron, ...
    ],
)
def test_a_desktop_terminal_skips_the_key_unless_all_is_local(login: FakeLogind, why: str) -> None:
    verdict = decide(sudo(), login)
    assert not verdict.local
    assert why in verdict.reason


def test_background_and_manager_sessions_do_not_count_as_logins() -> None:
    login = desktop_terminal(
        cron=Session(seat=None, kind="background"), m=Session(seat=None, kind="manager")
    )
    assert decide(sudo(), login).local


# The entry point pam_exec runs: it fails closed.


def test_main_says_yes_only_for_a_local_request() -> None:
    env = {"PAM_USER": "root", "PAM_SERVICE": "sudo", "PAM_TTY": "/dev/pts/0"}
    root_session = in_session(Session(uid=0))
    assert main(env, lambda: root_session) == 0
    assert main(env, lambda: in_session(Session(uid=0, remote=True))) == 1


@pytest.mark.parametrize(
    "env",
    [
        {},  # no PAM_USER
        {"PAM_USER": "no-such-user-fido2-ble-bridge", "PAM_SERVICE": "sudo"},
    ],
)
def test_main_fails_closed_without_a_known_user(env: dict[str, str]) -> None:
    assert main(env, lambda: in_session(Session(uid=0))) == 1


def test_main_fails_closed_when_logind_cannot_be_read() -> None:
    env = {"PAM_USER": "root", "PAM_SERVICE": "sudo"}
    assert main(env, lambda: FakeLogind(broken=True)) == 1

    def no_library() -> SdLogin:
        return SdLogin("libsystemd-that-does-not-exist.so.0")

    assert main(env, no_library) == 1


def test_main_leaves_no_alarm_behind() -> None:
    main({"PAM_USER": "root"}, lambda: in_session(Session(uid=0)))
    assert signal.alarm(0) == 0


@pytest.mark.parametrize(
    "extra",
    [{"PAM_USER": "no-such-user-fido2-ble-bridge"}, {"PAM_USER": "root", "PAM_RHOST": "x.test"}],
)
def test_the_module_run_as_pam_exec_runs_it_fails_closed(extra: dict[str, str]) -> None:
    # As pam_exec runs it: python -I -m ..., with only PAM's variables in the environment
    # (and -B, so that the test leaves no bytecode in the source tree).
    env = {"PAM_SERVICE": "sudo", "PAM_TYPE": "auth", **extra}
    done = subprocess.run(
        [sys.executable, "-I", "-B", "-m", "fido2_ble_bridge.local_session"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert done.returncode == 1, done.stderr
    assert "not using the key" in done.stderr


@pytest.mark.skipif(
    ctypes.util.find_library("systemd") is None and not os.path.exists("/run/systemd/system"),
    reason="needs libsystemd",
)
def test_the_sd_login_binding_reads_this_process() -> None:
    try:
        login = SdLogin()
    except LoginStateError as exc:
        pytest.skip(str(exc))
    session = login.session_of(0)
    owner = login.owner_uid_of(0)
    assert session is None or isinstance(session, str)
    assert owner is None or isinstance(owner, int)
    if session is not None:
        assert isinstance(login.is_remote(session), bool)
        assert isinstance(login.session_class(session), str)
        assert session in login.sessions(login.session_uid(session))
    assert isinstance(login.sessions(os.getuid()), list)
