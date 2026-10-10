"""End to end through the real kernel: uhid device, hidraw, libfido2, pamu2fcfg and pam_u2f.

Only the Bluetooth radio is simulated. Needs a writable /dev/uhid, read/write access to the
hidraw node udev creates (uaccess on a desktop seat, or a CI udev rule), fido2-token, pamu2fcfg
and pam_u2f.so. Tool paths can be overridden with FIDO2_TOKEN, PAMU2FCFG and PAM_U2F_SO.
"""

from __future__ import annotations

import asyncio
import getpass
import glob
import hashlib
import os
import secrets
import shutil
import subprocess
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pam_harness
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fakes import AAGUID, SimulatedConnector, SoftAuthenticator

from fido2_ble_bridge.ble_link import FidoBleLink
from fido2_ble_bridge.daemon import serve_device
from fido2_ble_bridge.uhid import UhidDevice

ORIGIN = "pam://fido2-ble-e2e"
SERVICE = "fido2-ble-e2e"
CMD_GET_ASSERTION = 0x02


def _pam_u2f_module() -> str | None:
    if os.environ.get("PAM_U2F_SO"):
        return os.environ["PAM_U2F_SO"]
    for pattern in (
        "/lib/*/security/pam_u2f.so",
        "/usr/lib/*/security/pam_u2f.so",
        "/usr/lib/security/pam_u2f.so",
        "/usr/lib64/security/pam_u2f.so",
    ):
        if found := sorted(glob.glob(pattern)):
            return found[0]
    return None


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
        for uevent in glob.glob("/sys/class/hidraw/hidraw*/device/uevent"):
            if f"HID_NAME={self.name}\n" in Path(uevent).read_text():
                return "/dev/" + Path(uevent).parent.parent.name
        return None

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


@pytest.fixture
def registered(bridge: tuple[BridgeThread, str], tmp_path: Path) -> tuple[SoftAuthenticator, Path]:
    if PAMU2FCFG is None or PAM_U2F_SO is None or not pam_harness.available():
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
    stack = stack_from_shipped_profile(authfile)
    for service in ("sudo", "sshd"):
        (confdir / service).write_text(stack)
    return thread.authenticator, confdir


PROFILE = Path(__file__).resolve().parent.parent / "packaging" / "pam-configs" / "fido2-ble-bridge"


def stack_from_shipped_profile(authfile: Path) -> str:
    """The auth stack pam-auth-update builds from the shipped profile.

    Mirrors its output on Ubuntu 24.04: the profile's Auth lines with `end` turned into a jump
    past the Primary block, then pam_unix (here pam_deny, a password that never matches), then
    the stock tail.
    """
    text = PROFILE.read_text()
    block = text.split("\nAuth:\n", 1)[1].split("\nAuth-Initial:", 1)[0]
    primary = [line.strip() for line in block.splitlines() if line.strip()]
    primary.append("[success=end default=ignore] pam_deny.so")
    lines = []
    for index, line in enumerate(primary):
        control, rest = line.split("]", 1)
        control = control.replace("end", str(len(primary) - index)) + "]"
        rest = rest.replace("pam_u2f.so", str(PAM_U2F_SO))
        rest = rest.replace("/etc/fido2-ble-bridge/u2f_mappings", str(authfile))
        rest = rest.replace("pam://fido2-ble-bridge", ORIGIN)
        lines.append(f"auth {control} {rest.strip()}")
    lines += ["auth requisite pam_deny.so", "auth required pam_permit.so"]
    return "\n".join(lines) + "\n"


def test_pam_u2f_login_with_fingerprint_succeeds(
    registered: tuple[SoftAuthenticator, Path],
) -> None:
    authenticator, confdir = registered
    result, messages = pam_harness.authenticate(confdir, SERVICE, getpass.getuser())
    assert result == pam_harness.PAM_SUCCESS
    assert any("touch" in m.lower() for m in messages)
    # pam_u2f probes silently for the credential, then asks with user verification.
    assert authenticator.commands.count(CMD_GET_ASSERTION) >= 2


def test_pam_u2f_login_fails_when_the_fingerprint_does_not_match(
    registered: tuple[SoftAuthenticator, Path],
) -> None:
    authenticator, confdir = registered
    authenticator.uv_succeeds = False
    result, _ = pam_harness.authenticate(confdir, SERVICE, getpass.getuser())
    assert result == pam_harness.PAM_AUTH_ERR


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
    result, _ = pam_harness.authenticate(confdir, SERVICE, getpass.getuser())
    assert result == pam_harness.PAM_AUTH_ERR


def test_shipped_pam_profile_uses_the_key_for_local_services(
    registered: tuple[SoftAuthenticator, Path],
) -> None:
    _, confdir = registered
    result, _ = pam_harness.authenticate(confdir, "sudo", getpass.getuser())
    assert result == pam_harness.PAM_SUCCESS


def test_shipped_pam_profile_never_wakes_the_key_for_sshd(
    registered: tuple[SoftAuthenticator, Path],
) -> None:
    # A remote login attempt must not make the key ask for a fingerprint: if the owner touched
    # it, the remote session would be the one let in.
    authenticator, confdir = registered
    before = list(authenticator.commands)
    result, messages = pam_harness.authenticate(confdir, "sshd", getpass.getuser())
    assert result == pam_harness.PAM_AUTH_ERR
    assert authenticator.commands == before
    assert not any("touch" in m.lower() for m in messages)
