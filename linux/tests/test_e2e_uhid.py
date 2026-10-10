"""End to end through the real kernel: uhid device, hidraw, libfido2, pamu2fcfg and pam_u2f.

Only the Bluetooth radio is simulated. Needs a writable /dev/uhid, read/write access to the
hidraw node udev creates (uaccess on a desktop seat, or a CI udev rule), fido2-token, pamu2fcfg
and pam_u2f.so. Tool paths can be overridden with FIDO2_TOKEN, PAMU2FCFG and PAM_U2F_SO, except
that setup's login test always uses the system's pam_u2f.so, as setup itself does.
"""

from __future__ import annotations

import asyncio
import getpass
import hashlib
import os
import secrets
import shutil
import subprocess
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fakes import AAGUID, SimulatedConnector, SoftAuthenticator
from pam_profile import CHECK, stack_from_profile
from setup_fakes import ScriptedConsole

from fido2_ble_bridge import pam
from fido2_ble_bridge.ble_link import FidoBleLink
from fido2_ble_bridge.daemon import serve_device
from fido2_ble_bridge.setup_wizard import Host, Paths, Setup, SetupOptions, find_hidraw_node
from fido2_ble_bridge.uhid import UhidDevice

ORIGIN = "pam://fido2-ble-e2e"
SERVICE = "fido2-ble-e2e"
CMD_MAKE_CREDENTIAL = 0x01
CMD_GET_ASSERTION = 0x02


def _pam_u2f_module() -> str | None:
    if os.environ.get("PAM_U2F_SO"):
        return os.environ["PAM_U2F_SO"]
    found = pam.find_pam_u2f()
    return str(found) if found else None


FIDO2_TOKEN = os.environ.get("FIDO2_TOKEN") or shutil.which("fido2-token")
PAMU2FCFG = os.environ.get("PAMU2FCFG") or shutil.which("pamu2fcfg")
PAM_U2F_SO = _pam_u2f_module()

pytestmark = [
    pytest.mark.uhid,
    pytest.mark.skipif(
        not os.access("/dev/uhid", os.R_OK | os.W_OK), reason="/dev/uhid is not writable"
    ),
    pytest.mark.skipif(FIDO2_TOKEN is None, reason="fido2-token (libfido2) not found"),
]


class BridgeThread:
    """The real daemon loop (serve_device) on a real uhid device, with a simulated radio."""

    def __init__(self, authenticator: SoftAuthenticator) -> None:
        self.name = f"fido2-ble-bridge-test-{secrets.token_hex(4)}"
        self.authenticator = authenticator
        self.error: BaseException | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop: asyncio.Event | None = None
        self._started = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        try:
            asyncio.run(self._main())
        except BaseException as exc:
            self.error = exc
            self._started.set()

    async def _main(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._stop = asyncio.Event()
        link = FidoBleLink(SimulatedConnector(self.authenticator), idle_disconnect=30)
        self._started.set()
        try:
            with UhidDevice() as device:
                await serve_device(device, link, name=self.name, connect_timeout=5, stop=self._stop)
        finally:
            await link.close()

    def start(self) -> str:
        self._thread.start()
        self._started.wait(5)
        if self.error is not None:
            raise self.error
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            node = self._find_node()
            if node and os.access(node, os.R_OK | os.W_OK):
                return node
            time.sleep(0.05)
        self.stop()
        pytest.skip(
            "no read/write access to the virtual hidraw node (no uaccess seat or udev rule)"
        )

    def _find_node(self) -> str | None:
        # What setup uses too: matched by HID name, and only under the uhid device tree.
        return find_hidraw_node(Path("/sys/class/hidraw"), self.name)

    def stop(self) -> None:
        if self._loop is not None and self._stop is not None:
            self._loop.call_soon_threadsafe(self._stop.set)
        self._thread.join(10)


@pytest.fixture
def authenticator() -> SoftAuthenticator:
    return SoftAuthenticator(user_wait=0.2)


@pytest.fixture
def bridge(authenticator: SoftAuthenticator) -> Iterator[tuple[BridgeThread, str]]:
    thread = BridgeThread(authenticator)
    node = thread.start()
    yield thread, node
    thread.stop()
    assert thread.error is None, thread.error


def run(*args: str) -> str:
    done = subprocess.run(args, capture_output=True, text=True, timeout=60, check=False)
    if done.returncode != 0:
        pytest.fail(f"{Path(args[0]).name} exited {done.returncode}: {done.stderr.strip()}")
    return done.stdout


def listed_devices() -> list[str]:
    assert FIDO2_TOKEN is not None
    return [line.split(":")[0] for line in run(FIDO2_TOKEN, "-L").splitlines() if line]


def test_libfido2_enumerates_and_queries_the_virtual_key(
    bridge: tuple[BridgeThread, str],
) -> None:
    _, node = bridge
    assert FIDO2_TOKEN is not None
    assert node in listed_devices()
    info = run(FIDO2_TOKEN, "-I", node)
    assert "FIDO_2_0" in info
    assert AAGUID.hex() in info


def test_setup_reads_registers_and_tests_the_key_with_the_real_tools(
    bridge: tuple[BridgeThread, str], tmp_path: Path
) -> None:
    # setup's fingerprint check, registration and PAM test, run against real fido2-token,
    # pamu2fcfg and pam_u2f (the system's module: the test stack names it as the profile does).
    if os.environ.get("PAM_U2F_SO") and pam.find_pam_u2f() is None:
        pytest.skip("setup's login test uses the system's pam_u2f.so; PAM_U2F_SO is not used here")
    if PAMU2FCFG is None or pam.find_pam_u2f() is None or not pam.available():
        pytest.skip("pamu2fcfg, the system's pam_u2f.so or pam_start_confdir not available")
    thread, node = bridge
    if listed_devices() != [node]:
        pytest.skip("another FIDO device is attached; pamu2fcfg would pick the wrong one")
    assert FIDO2_TOKEN is not None
    user = getpass.getuser()
    console = ScriptedConsole("")  # no backup key
    host = Host(console=console, paths=Paths(tmp_path), euid=os.geteuid(), sudo_user=user)
    setup = Setup(SetupOptions(user=user), host)
    setup.user = user
    setup.tools = {"pamu2fcfg": PAMU2FCFG, "fido2-token": FIDO2_TOKEN}

    assert "uv" in setup._key_options(node)
    assert setup.register(node, thread.name) == node
    assert not host.paths.mappings.exists()  # saved only once the login test passed
    assert setup.test_login(node) is True
    assert host.paths.mappings.read_text().startswith(f"{user}:")
    assert any(line.startswith("  pam_u2f: ") and "touch" in line.lower() for line in console.lines)
    assert thread.authenticator.commands.count(CMD_MAKE_CREDENTIAL) == 1
    assert console.answers == []


@pytest.fixture
def registered(bridge: tuple[BridgeThread, str], tmp_path: Path) -> tuple[SoftAuthenticator, Path]:
    if PAMU2FCFG is None or PAM_U2F_SO is None or not pam.available():
        pytest.skip("pamu2fcfg, pam_u2f.so or pam_start_confdir not available")
    thread, node = bridge
    if listed_devices() != [node]:
        pytest.skip("another FIDO device is attached; pamu2fcfg would pick the wrong one")
    user = getpass.getuser()
    line = run(PAMU2FCFG, "-u", user, "-o", ORIGIN, "-i", ORIGIN, "-V").strip()
    assert line.startswith(f"{user}:")
    authfile = tmp_path / "u2f_keys"
    authfile.write_text(line + "\n")
    confdir = tmp_path / "pam.d"
    confdir.mkdir()
    (confdir / SERVICE).write_text(
        f"auth required {PAM_U2F_SO} authfile={authfile} origin={ORIGIN} cue userverification=1\n"
    )
    # The shipped profile's stack twice: once with the local-session check saying "local"
    # (exit 0), once saying "not local", as it does for a request from an SSH session.
    for directory, verdict in ((confdir, "true"), (remote_confdir(confdir), "false")):
        directory.mkdir(exist_ok=True)
        program = shutil.which(verdict)
        assert program is not None
        stack = stack_from_profile(
            {
                "pam_u2f.so": str(PAM_U2F_SO),
                "/etc/fido2-ble-bridge/u2f_mappings": str(authfile),
                "pam://fido2-ble-bridge": ORIGIN,
                CHECK: program,
            }
        )
        for service in ("sudo", "sshd", "su", "polkit-1"):
            (directory / service).write_text(stack)
    return thread.authenticator, confdir


def remote_confdir(confdir: Path) -> Path:
    return confdir.with_name("pam.d-remote")


def test_pam_u2f_login_with_fingerprint_succeeds(
    registered: tuple[SoftAuthenticator, Path],
) -> None:
    authenticator, confdir = registered
    outcome = pam.authenticate(confdir, SERVICE, getpass.getuser())
    assert outcome.code == pam.PAM_SUCCESS
    assert any("touch" in m.lower() for m in outcome.messages)
    # pam_u2f probes silently for the credential, then asks with user verification.
    assert authenticator.commands.count(CMD_GET_ASSERTION) >= 2


def test_pam_u2f_login_fails_when_the_fingerprint_does_not_match(
    registered: tuple[SoftAuthenticator, Path],
) -> None:
    authenticator, confdir = registered
    authenticator.uv_succeeds = False
    outcome = pam.authenticate(confdir, SERVICE, getpass.getuser())
    assert outcome.code == pam.PAM_AUTH_ERR


def test_pam_u2f_rejects_a_key_that_signs_with_the_wrong_private_key(
    registered: tuple[SoftAuthenticator, Path],
) -> None:
    # What a fake key, or a compromised bridge, can do at best: answer for the right
    # credential ID without the matching private key. pam_u2f must refuse.
    authenticator, confdir = registered
    rp_id_hash = hashlib.sha256(ORIGIN.encode()).digest()
    for credential_id in list(authenticator.credentials):
        authenticator.credentials[credential_id] = (
            rp_id_hash,
            ec.generate_private_key(ec.SECP256R1()),
        )
    outcome = pam.authenticate(confdir, SERVICE, getpass.getuser())
    assert outcome.code == pam.PAM_AUTH_ERR


def test_shipped_pam_profile_uses_the_key_for_local_services(
    registered: tuple[SoftAuthenticator, Path],
) -> None:
    _, confdir = registered
    outcome = pam.authenticate(confdir, "sudo", getpass.getuser())
    assert outcome.code == pam.PAM_SUCCESS


@pytest.mark.parametrize("service", ["sshd", "su", "polkit-1"])
def test_shipped_pam_profile_never_wakes_the_key_for_sshd_su_or_polkit(
    registered: tuple[SoftAuthenticator, Path], service: str
) -> None:
    # A remote login attempt must not make the key ask for a fingerprint: if the owner touched
    # it, the remote session would be the one let in. su and polkit let the caller name the
    # account to log in as, so anyone could make the owner's key ask.
    authenticator, confdir = registered
    before = list(authenticator.commands)
    outcome = pam.authenticate(confdir, service, getpass.getuser())
    assert outcome.code == pam.PAM_AUTH_ERR
    assert authenticator.commands == before
    assert not any("touch" in m.lower() for m in outcome.messages)


def test_shipped_pam_profile_skips_the_key_for_sudo_outside_a_local_session(
    registered: tuple[SoftAuthenticator, Path],
) -> None:
    authenticator, confdir = registered
    before = list(authenticator.commands)
    outcome = pam.authenticate(remote_confdir(confdir), "sudo", getpass.getuser())
    assert outcome.code == pam.PAM_AUTH_ERR
    assert authenticator.commands == before
    assert not any("touch" in m.lower() for m in outcome.messages)
