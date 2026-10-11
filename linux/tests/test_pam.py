"""The pam_start_confdir binding, against the system's real libpam and its stock modules."""

from __future__ import annotations

import getpass
import os
from pathlib import Path

import pytest

from fido2_ble_bridge import pam

needs_confdir = pytest.mark.skipif(
    not pam.available(), reason="needs Linux-PAM 1.4 or newer (pam_start_confdir)"
)


def stack(tmp_path: Path, *lines: str) -> Path:
    (tmp_path / "test-service").write_text("".join(f"{line}\n" for line in lines))
    return tmp_path


@needs_confdir
def test_a_stack_that_permits_succeeds(tmp_path: Path) -> None:
    result = pam.authenticate(
        stack(tmp_path, "auth required pam_permit.so"), "test-service", getpass.getuser()
    )
    assert result.ok
    assert result.code == pam.PAM_SUCCESS


@needs_confdir
def test_a_stack_that_denies_fails_with_a_description(tmp_path: Path) -> None:
    result = pam.authenticate(
        stack(tmp_path, "auth required pam_deny.so"), "test-service", getpass.getuser()
    )
    assert result.code == pam.PAM_AUTH_ERR
    assert not result.ok
    assert result.description


@needs_confdir
def test_module_messages_reach_the_callback_as_they_arrive(tmp_path: Path) -> None:
    seen: list[str] = []
    confdir = stack(
        tmp_path, "auth optional pam_echo.so Touch the sensor", "auth required pam_permit.so"
    )
    result = pam.authenticate(confdir, "test-service", getpass.getuser(), seen.append)
    assert seen == ["Touch the sensor"]
    assert result.messages == ["Touch the sensor"]
    assert result.ok


@needs_confdir
def test_a_failing_message_callback_stays_out_of_c(tmp_path: Path) -> None:
    def broken(_text: str) -> None:
        raise RuntimeError("terminal gone")

    confdir = stack(tmp_path, "auth optional pam_echo.so hello", "auth required pam_permit.so")
    # Kept out of C, where ctypes would only print it, and raised once PAM is done.
    with pytest.raises(RuntimeError, match="terminal gone"):
        pam.authenticate(confdir, "test-service", getpass.getuser(), broken)


@needs_confdir
def test_ctrl_c_in_the_conversation_fails_it_and_is_raised_after_pam(tmp_path: Path) -> None:
    # SIGINT turns into KeyboardInterrupt in whatever Python code runs next, which during a
    # login test is the conversation callback. ctypes used to swallow it, and PAM went on as if
    # the conversation had succeeded.
    seen: list[str] = []

    def interrupted(text: str) -> None:
        seen.append(text)
        raise KeyboardInterrupt

    confdir = stack(
        tmp_path,
        "auth optional pam_echo.so first",
        "auth optional pam_echo.so second",
        "auth required pam_permit.so",
    )
    with pytest.raises(KeyboardInterrupt):
        pam.authenticate(confdir, "test-service", getpass.getuser(), interrupted)
    assert seen == ["first"]  # every later conversation fails at once


@needs_confdir
def test_a_missing_stack_is_an_error_not_a_login(tmp_path: Path) -> None:
    with pytest.raises(pam.PamError):
        pam.authenticate(tmp_path, "no-such-service", getpass.getuser())


def _pam_u2f() -> str | None:
    module = os.environ.get("PAM_U2F_SO") or pam.find_pam_u2f()
    return str(module) if module else None


@needs_confdir
@pytest.mark.skipif(_pam_u2f() is None, reason="pam_u2f.so not installed")
def test_pam_u2f_uses_only_the_last_line_of_a_user(tmp_path: Path) -> None:
    # Why setup replaces all of a user's lines, and adds backup keys to the last one.
    user = getpass.getuser()
    cred = "{},UHVibGljS2V5,es256,+presence+verification"
    authfile = tmp_path / "authfile"
    authfile.write_text(
        f"{user}:{cred.format('T0xEMQ==')}:{cred.format('T0xEMg==')}\n{user}:{cred.format('TkVX')}\n"
    )
    log = tmp_path / "debug.log"
    log.write_text("")
    # `manual` keeps pam_u2f away from this machine's FIDO devices: with a bridge installed it
    # would otherwise make the bridge reach for the real key. The authfile is read either way.
    confdir = stack(
        tmp_path,
        f"auth required {_pam_u2f()} debug debug_file={log} authfile={authfile} "
        f"origin={pam.ORIGIN} manual userverification=1",
    )
    result = pam.authenticate(confdir, "test-service", user)
    assert not result.ok  # the conversation answers pam_u2f's challenge with nothing
    assert f"Found 1 device(s) for user {user}" in log.read_text()


def test_pam_u2f_is_found_in_the_usual_module_directories(tmp_path: Path) -> None:
    assert pam.find_pam_u2f(tmp_path) is None
    module = tmp_path / "usr/lib64/security/pam_u2f.so"
    module.parent.mkdir(parents=True)
    module.touch()
    assert pam.find_pam_u2f(tmp_path) == module
    multiarch = tmp_path / "usr/lib/x86_64-linux-gnu/security/pam_u2f.so"
    multiarch.parent.mkdir(parents=True)
    multiarch.touch()
    assert pam.find_pam_u2f(tmp_path) == multiarch


def test_pam_u2f_arguments_require_the_fingerprint_and_a_fixed_origin() -> None:
    assert pam.u2f_arguments(Path("/etc/fido2-ble-bridge/u2f_mappings")) == (
        "authfile=/etc/fido2-ble-bridge/u2f_mappings origin=pam://fido2-ble-bridge cue "
        "userverification=1"
    )


AUTHFILE = Path("/etc/fido2-ble-bridge/u2f_mappings")
SHIPPED = pam.u2f_arguments(AUTHFILE).split()


def test_the_shipped_pam_u2f_arguments_pass_the_option_check() -> None:
    assert pam.u2f_option_problems(SHIPPED, AUTHFILE) == []
    harmless = [*SHIPPED, "max_devices=4", "cue_prompt=Touch", "interactive", "debug"]
    assert pam.u2f_option_problems(harmless, AUTHFILE) == []


@pytest.mark.parametrize(
    ("change", "problem"),
    [
        (["alwaysok"], "alwaysok"),
        (["nouserok"], "nouserok"),
        (["openasuser"], "openasuser"),
        (["expand"], "expand"),
        (["manual"], "manual"),
        (["sshformat"], "sshformat"),
        (["conf=/tmp/x.conf"], "conf=/tmp/x.conf"),
        (["userverification=0"], "no userverification=1"),  # the last value counts
        (["userpresence=0"], "userpresence=0"),
        (["authfile=/home/alice/.u2f_keys"], "authfile is not /etc/fido2-ble-bridge/u2f_mappings"),
        (["some_future_option"], "some_future_option"),
    ],
)
def test_weakening_or_unknown_pam_u2f_options_are_reported(change: list[str], problem: str) -> None:
    assert problem in pam.u2f_option_problems([*SHIPPED, *change], AUTHFILE)


def test_a_line_without_userverification_is_reported() -> None:
    arguments = [argument for argument in SHIPPED if not argument.startswith("userverification")]
    assert pam.u2f_option_problems(arguments, AUTHFILE) == ["no userverification=1"]


def test_pam_u2f_config_file_settings_read_like_module_arguments() -> None:
    text = "# defaults\nnouserok\n  cue_prompt = Touch it  # comment\n\nmax_devices=2\n"
    assert pam.config_file_arguments(text) == ["nouserok", "cue_prompt=Touch it", "max_devices=2"]


def test_the_pam_u2f_lines_of_a_profile_are_found_in_both_auth_blocks() -> None:
    profile = (
        "Name: x\nAuth-Type: Primary\nAuth:\n"
        "\t[success=ignore default=1]\tpam_succeed_if.so quiet service in sudo\n"
        "\t[success=end default=ignore]\tpam_u2f.so authfile=/a cue\n"
        "Auth-Initial:\n"
        "\tsufficient\t/lib/security/pam_u2f.so authfile=/b\n"
        "Account:\n"
        "\trequired\tpam_u2f.so authfile=/c\n"
    )
    assert pam.profile_u2f_lines(profile) == [
        ("pam_u2f.so", "authfile=/a", "cue"),
        ("/lib/security/pam_u2f.so", "authfile=/b"),
    ]
