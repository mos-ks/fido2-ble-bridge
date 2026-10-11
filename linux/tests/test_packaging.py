"""The shipped packaging files agree with the code, with each other and with the README."""

import getpass
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from pam_profile import CHECK, HINT, U2F_LINE, stack_from_profile

from fido2_ble_bridge import pam
from fido2_ble_bridge.config import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_MAPPINGS_PATH,
    PLACEHOLDER_ADDRESS,
    Config,
    load_config,
)
from fido2_ble_bridge.daemon import UHID_FD_NAME
from fido2_ble_bridge.setup_wizard import PAM_PROFILE, UNIT

PROJECT = Path(__file__).resolve().parents[1]
PACKAGING = PROJECT / "packaging"
INSTALL_SH = PROJECT / "install.sh"
PAM_U2F_ARGS = pam.u2f_arguments(DEFAULT_MAPPINGS_PATH)


def shell_variable(name: str) -> str:
    match = re.search(rf'^{name}="?([^"\n]*)"?$', INSTALL_SH.read_text(), re.MULTILINE)
    assert match is not None, f"{name}= not found in install.sh"
    return match.group(1)


def unit_settings(name: str) -> list[str]:
    lines = (PACKAGING / "fido2-ble-bridge.service").read_text().splitlines()
    return [line.split("=", 1)[1] for line in lines if line.startswith(f"{name}=")]


def pam_profile_blocks() -> dict[str, list[str]]:
    """The profile's multi-line fields (Auth, Auth-Initial, ...) as lists of lines."""
    blocks: dict[str, list[str]] = {}
    field: str | None = None
    for line in (PACKAGING / "pam-configs" / "fido2-ble-bridge").read_text().splitlines():
        if line[:1].isspace():
            assert field is not None, f"continuation line outside a field: {line!r}"
            blocks[field].append(line.strip())
        elif line.endswith(":"):
            field = line[:-1]
            blocks[field] = []
        else:
            field = None
    return blocks


def test_example_config_is_valid_and_matches_the_installer_placeholder() -> None:
    placeholder = shell_variable("placeholder")
    assert placeholder == PLACEHOLDER_ADDRESS
    assert load_config(PACKAGING / "config.toml.example") == Config(address=placeholder)


def test_unit_runs_the_installed_package_with_the_default_config() -> None:
    assert Path(shell_variable("config_dir")) == DEFAULT_CONFIG_PATH.parent
    assert shell_variable("unit_path") == f"/etc/systemd/system/{UNIT}.service"
    assert shell_variable("pam_profile") == f"/usr/share/pam-configs/{PAM_PROFILE}"
    assert unit_settings("ExecStart") == [
        f"{shell_variable('prefix')}/bin/python -I -m fido2_ble_bridge run "
        f"--config {DEFAULT_CONFIG_PATH}"
    ]
    assert unit_settings("OpenFile") == [f"/dev/uhid:{UHID_FD_NAME}"]
    assert unit_settings("DeviceAllow") == ["/dev/uhid rw"]


def test_service_user_is_static_and_may_reach_bluez() -> None:
    # dbus-daemon resets connections from DynamicUser services, which cut the bridge off from
    # BlueZ; the service runs as a sysusers.d user that a D-Bus policy lets talk to org.bluez.
    assert unit_settings("DynamicUser") == []
    assert unit_settings("User") == ["fido2-ble-bridge"]
    assert unit_settings("Group") == ["fido2-ble-bridge"]
    sysusers = (PACKAGING / "fido2-ble-bridge.sysusers").read_text().splitlines()
    assert [line.split()[:2] for line in sysusers if line and not line.startswith("#")] == [
        ["u", "fido2-ble-bridge"]
    ]
    policy = (PACKAGING / "fido2-ble-bridge-dbus.conf").read_text()
    assert '<policy user="fido2-ble-bridge">' in policy
    assert '<allow send_destination="org.bluez"/>' in policy
    assert shell_variable("sysusers_path") == "/etc/sysusers.d/fido2-ble-bridge.conf"
    assert shell_variable("dbus_policy_path") == "/etc/dbus-1/system.d/fido2-ble-bridge.conf"
    uninstall = (PROJECT / "uninstall.sh").read_text()
    assert "/etc/dbus-1/system.d/fido2-ble-bridge.conf" in uninstall
    assert "/etc/sysusers.d/fido2-ble-bridge.conf" in uninstall


def _services(guard: str) -> set[str]:
    return set(guard.split("pam_succeed_if.so quiet service in ", 1)[1].split(":"))


def test_pam_profile_uses_the_key_only_for_local_services() -> None:
    blocks = pam_profile_blocks()
    assert blocks["Auth"] == blocks["Auth-Initial"]
    keyed, seat_only, check, hint, u2f = blocks["Auth"]
    # Not a listed service: skip the other four lines.
    assert keyed.startswith("[success=ignore default=4]\t")
    # Login screens and lock screens skip the check; everything else goes through it.
    assert seat_only.startswith("[success=1 default=ignore]\t")
    # A failed check skips the hint and the key.
    assert check == f"[success=ignore default=2]\tpam_exec.so quiet {pam.LOCAL_SESSION_CHECK}"
    # The hint can never change the result, and holds nothing PAM would read as syntax.
    assert hint == f"[default=ignore]\tpam_echo.so {HINT}"
    assert HINT == pam.KEY_HINT  # what setup prints for systems without pam-auth-update
    assert not set("[]%") & set(HINT)
    assert u2f == f"[success=end default=ignore]\tpam_u2f.so {PAM_U2F_ARGS}"
    assert _services(seat_only) < _services(keyed)
    assert _services(keyed) - _services(seat_only) == {"sudo", "sudo-i", "login"}
    assert {"gdm-password", "sddm", "lightdm"} <= _services(seat_only)
    # su and polkit authenticate whichever account the caller names; sshd is remote.
    assert not {"su", "su-l", "polkit-1", "sshd", "remote"} & _services(keyed)


def test_the_local_session_check_runs_the_installed_package() -> None:
    python, *arguments = pam.LOCAL_SESSION_CHECK.split()
    assert python == f"{shell_variable('prefix')}/bin/python"
    assert arguments[:2] == ["-I", "-m"]  # -I: never imports from the caller's directory
    module = PROJECT / "src" / (arguments[2].replace(".", "/") + ".py")
    assert module.is_file()


@pytest.mark.skipif(not pam.available(), reason="needs Linux-PAM 1.4 or newer")
@pytest.mark.parametrize(
    ("service", "local", "asks_key"),
    [
        ("gdm-password", False, True),  # login and lock screens need no check
        ("lightdm", False, True),
        ("sudo", True, True),
        ("sudo", False, False),  # sudo in an SSH session, say
        ("sudo-i", False, False),
        ("login", True, True),
        ("login", False, False),
        ("su", True, False),  # su and polkit name the account to log in as
        ("su-l", True, False),
        ("polkit-1", True, False),
        ("sshd", True, False),
        ("cron", True, False),
    ],
)
def test_the_profile_s_stack_reaches_the_key_only_where_it_should(
    tmp_path: Path, service: str, local: bool, asks_key: bool
) -> None:
    verdict = shutil.which("true" if local else "false")
    assert verdict is not None
    # The real libpam, pam_succeed_if and pam_exec; pam_echo stands in for pam_u2f and a
    # program exiting 0 or 1 for the local-session check.
    (tmp_path / service).write_text(
        stack_from_profile({U2F_LINE: "pam_echo.so KEY-ASKED", CHECK: verdict})
    )
    result = pam.authenticate(tmp_path, service, getpass.getuser())
    assert ("KEY-ASKED" in result.messages) is asks_key
    # The hint comes first, and only where the key is asked.
    assert result.messages[:2] == ([HINT, "KEY-ASKED"] if asks_key else [])
    assert result.ok is asks_key  # without the key, the password (pam_deny here) fails


@pytest.mark.skipif(not pam.available(), reason="needs Linux-PAM 1.4 or newer")
@pytest.mark.parametrize("service", ["sudo", "su", "sshd"])
def test_a_skipped_key_leaves_the_password_working(tmp_path: Path, service: str) -> None:
    # The failed check (or pam_succeed_if) only jumps: it must not fail the stack, or sudo in an
    # SSH session could not be used at all.
    verdict = shutil.which("false")
    assert verdict is not None
    stack = stack_from_profile(
        {U2F_LINE: "pam_echo.so KEY-ASKED", CHECK: verdict}, fallback_module="pam_permit.so"
    )
    (tmp_path / service).write_text(stack)
    result = pam.authenticate(tmp_path, service, getpass.getuser())
    assert "KEY-ASKED" not in result.messages
    assert HINT not in result.messages
    assert result.ok


def test_readme_documents_the_profile_s_pam_u2f_arguments() -> None:
    readme = (PROJECT / "README.md").read_text()
    assert f"auth required pam_u2f.so {PAM_U2F_ARGS}" in readme
    assert f"auth sufficient pam_u2f.so {PAM_U2F_ARGS}" in readme
    assert f"auth [success=ignore default=2] pam_exec.so quiet {pam.LOCAL_SESSION_CHECK}" in readme
    assert f"auth [default=ignore] pam_echo.so {pam.KEY_HINT}" in readme
    assert f"-o {pam.ORIGIN} -i {pam.ORIGIN} -V" in readme


def test_readme_leads_with_the_installer_and_setup() -> None:
    readme = (PROJECT / "README.md").read_text()
    assert "sudo ./install.sh" in readme
    assert "sudo fido2-ble-bridge setup" in readme
    assert "packaging/install.sh" not in readme


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize("script", ["install.sh", "uninstall.sh"])
def test_shell_scripts_parse(script: str) -> None:
    subprocess.run(["bash", "-n", str(PROJECT / script)], check=True)


def test_project_license_is_the_repository_license() -> None:
    repository_license = PROJECT.parent / "LICENSE"
    if not repository_license.exists():
        pytest.skip("not inside the repository checkout")
    assert (PROJECT / "LICENSE").read_text() == repository_license.read_text()
