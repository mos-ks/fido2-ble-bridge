"""`fido2-ble-bridge setup`, step by step, against fakes for BlueZ, commands, PAM and the key."""

from __future__ import annotations

import dataclasses
import re
import stat
from pathlib import Path
from typing import Any

import pytest
from dbus_fast.errors import DBusError
from fakes import SimulatedConnector
from setup_fakes import (
    ADAPTER_ADDRESS,
    ADAPTER_PATH,
    KEY,
    MAPPING,
    NODE,
    USER,
    FakeBluez,
    FakePam,
    FakeRunner,
    ScriptedConsole,
    SystemState,
    add_hidraw,
    device_path,
    healthy_runner,
    make_root,
    token_info,
)

from fido2_ble_bridge import daemon
from fido2_ble_bridge.ble_link import KeyNotReachable, KeyNotTrusted
from fido2_ble_bridge.config import PLACEHOLDER_ADDRESS, Config, load_config
from fido2_ble_bridge.console import device_name
from fido2_ble_bridge.daemon import CheckResult
from fido2_ble_bridge.pairing import ADAPTER, AGENT_CAPABILITY, AGENT_PATH, Bus
from fido2_ble_bridge.pam import LOCAL_SESSION_CHECK, ORIGIN, PamResult
from fido2_ble_bridge.setup_wizard import (
    AmbiguousDevice,
    Completed,
    Host,
    Paths,
    Setup,
    SetupError,
    SetupOptions,
    SystemRunner,
    Timing,
    credential_count,
    distro_family,
    find_hidraw_node,
    find_hidraw_nodes,
    has_bluetooth_adapter,
    mapping_line,
    mapping_lines,
    merge_mapping,
    parse_options,
    parse_version,
    resolve_user,
    set_adapter,
    set_address,
    valid_link_parameters,
    with_link_parameters,
)

FAST = Timing(scan=0.3, settle=0.05, poll=0.01, pair=0.3, wake=1.0, node=0.1)
PAMU2FCFG = ["pamu2fcfg", "-u", USER, "-o", ORIGIN, "-i", ORIGIN, "-V"]
BRIDGE = "FIDO2 BLE bridge"
PAM_ENABLED = (
    "auth [success=2 default=ignore] pam_u2f.so "
    f"authfile=/etc/fido2-ble-bridge/u2f_mappings origin={ORIGIN} cue userverification=1"
)


@dataclasses.dataclass
class World:
    """A freshly installed Ubuntu-like system with one key in pairing mode nearby."""

    paths: Paths
    state: SystemState
    runner: FakeRunner
    bluez: FakeBluez
    pam: FakePam
    console: ScriptedConsole
    check_result: CheckResult
    checks: list[tuple[Config, float]]
    euid: int = 0

    def host(self) -> Host:
        async def bus() -> Bus:
            self.bluez.disconnected = False  # a new connection for each run
            return self.bluez

        async def check(config: Config, timeout: float) -> CheckResult:
            self.checks.append((config, timeout))
            return self.check_result

        return Host(
            console=self.console,
            runner=self.runner,
            paths=self.paths,
            bus=bus,
            pam=self.pam,
            check=check,
            euid=self.euid,
            sudo_user=USER,
            user_exists=lambda name: name in {USER, "root"},
            timing=FAST,
        )

    def answer(self, *answers: str) -> None:
        self.console = ScriptedConsole(*answers)

    def run(self, **options: Any) -> int:
        return Setup(SetupOptions(**options), self.host()).run()

    def setup(self, **options: Any) -> Setup:
        """A Setup positioned after the prerequisites, for running single steps."""
        setup = Setup(SetupOptions(**options), self.host())
        setup.user = USER
        setup.tools = {name: f"/usr/bin/{name}" for name in ("pamu2fcfg", "fido2-token")}
        return setup


@pytest.fixture
def world(tmp_path: Path) -> World:
    paths = make_root(tmp_path)
    state = SystemState()
    bluez = FakeBluez()
    bluez.in_pairing_mode.add(KEY)
    add_hidraw(tmp_path, BRIDGE)
    return World(
        paths=paths,
        state=state,
        runner=healthy_runner(paths, state),
        bluez=bluez,
        pam=FakePam(),
        console=ScriptedConsole(),
        check_result=CheckResult(True, "bonded and encrypted link, FIDO2 selected."),
        checks=[],
    )


def config_for(address: str) -> Config:
    return Config(address=address)


# The whole run


def test_first_run_pairs_configures_registers_tests_and_enables_the_key(world: World) -> None:
    pam_tests_before_enabling: list[int] = []
    enable = world.runner._handlers[0][1]  # pam-auth-update, registered last

    def enable_after_test(argv: list[str]) -> Completed:
        pam_tests_before_enabling.append(len(world.pam.calls))
        assert callable(enable)
        return enable(argv)

    world.runner.on("pam-auth-update", "--enable", "fido2-ble-bridge", result=enable_after_test)
    # Enter once the key blinks; type yes to pair that key; no backup key; yes to enable PAM.
    world.answer("", "yes", "", "yes")
    assert world.run() == 0

    config_text = world.paths.config.read_text()
    assert f'address = "{KEY}"' in config_text
    assert "# Bluetooth adapter, if you have more than one." in config_text
    assert load_config(world.paths.config) == Config(address=KEY)
    assert world.paths.mappings.read_text() == MAPPING + "\n"
    assert stat.S_IMODE(world.paths.mappings.stat().st_mode) == 0o644

    assert world.runner.ran("pamu2fcfg") == [PAMU2FCFG]
    # The test names a temporary authfile holding only the new credential.
    ((service, user, stack),) = world.pam.calls
    assert (service, user) == ("fido2-ble-bridge-setup-test", USER)
    assert re.fullmatch(
        rf"auth required pam_u2f\.so authfile=\S+/u2f_mappings origin={re.escape(ORIGIN)} cue "
        r"userverification=1\n",
        stack,
    )
    assert str(world.paths.mappings) not in stack
    assert world.pam.authfiles == [MAPPING + "\n"]
    assert pam_tests_before_enabling == [1]
    enable_index = world.runner.calls.index(["pam-auth-update", "--enable", "fido2-ble-bridge"])
    assert world.runner.options[enable_index]["env"] == {"DEBIAN_FRONTEND": "noninteractive"}
    assert world.state.service_enabled and world.state.service_active

    members = world.bluez.members()
    assert members.index("RegisterAgent") < members.index("Pair") < members.index("UnregisterAgent")
    assert world.bluez.device(KEY)["Trusted"] is True
    assert world.bluez.agents == {}
    assert world.bluez.exported == {}
    assert world.bluez.disconnected

    text = world.console.text
    for undo in (
        f"undo: bluetoothctl remove {KEY}",
        "undo: sudo systemctl disable --now fido2-ble-bridge",
        "undo: sudo pam-auth-update --disable fido2-ble-bridge",
    ):
        assert undo in text
    assert "Setup is complete. Local logins, sudo and the lock screen accept the key." in text
    assert world.console.answers == []


def test_running_setup_again_changes_nothing_and_needs_no_fingerprint(world: World) -> None:
    world.answer("", "yes", "", "yes")
    assert world.run() == 0
    pamu2fcfg_runs = len(world.runner.ran("pamu2fcfg"))

    # Use the bonded key; keep the registration (default no); no backup key.
    world.answer("yes", "", "")
    assert world.run() == 0
    assert len(world.runner.ran("pamu2fcfg")) == pamu2fcfg_runs
    assert len(world.pam.calls) == 1
    assert world.bluez.members().count("Pair") == 1
    assert "Nothing on this system was changed." in world.console.text
    assert world.console.answers == []


def test_setup_refuses_to_run_without_root(world: World) -> None:
    world.euid = 1000
    assert world.run() == 1
    assert "must run as root" in world.console.text
    assert "Nothing on this system was changed." in world.console.text
    assert world.runner.calls == []
    assert world.bluez.calls == []


@pytest.mark.parametrize(
    ("explicit", "sudo_user", "expected"),
    [
        (None, "alice", "alice"),
        ("bob", "alice", "bob"),
        ("root", None, "root"),
    ],
)
def test_the_target_user_is_the_sudo_user_unless_named(
    explicit: str | None, sudo_user: str | None, expected: str
) -> None:
    assert resolve_user(explicit, sudo_user, lambda _name: True) == expected


@pytest.mark.parametrize("sudo_user", [None, "", "root"])
def test_root_is_only_set_up_when_asked_for_by_name(sudo_user: str | None) -> None:
    with pytest.raises(SetupError, match="--user root"):
        resolve_user(None, sudo_user, lambda _name: True)


def test_an_unknown_user_is_refused() -> None:
    with pytest.raises(SetupError, match="no user account named 'mallory'"):
        resolve_user("mallory", "alice", lambda name: name == "alice")


# Step 1: prerequisites


def test_prerequisites_report_versions(world: World) -> None:
    world.setup().prerequisites()
    assert (
        "OK: BlueZ 5.72, systemd 255, uhid, pam_u2f, pamu2fcfg, fido2-token." in world.console.text
    )


def test_missing_tools_are_installed_with_apt_after_asking(world: World) -> None:
    world.runner.tools -= {"pamu2fcfg", "fido2-token"}

    def install(_argv: list[str]) -> Completed:
        world.runner.tools |= {"pamu2fcfg", "fido2-token"}
        return Completed(0)

    world.runner.on("apt-get", "install", result=install)
    world.answer("y")
    setup = world.setup()
    setup.prerequisites()
    assert world.runner.ran("apt-get") == [["apt-get", "install", "-y", "fido2-tools", "pamu2fcfg"]]
    assert world.runner.options[world.runner.calls.index(world.runner.ran("apt-get")[0])][
        "interactive"
    ]
    assert setup.changes[0].undo == "sudo apt-get remove fido2-tools pamu2fcfg"
    assert world.console.answers == []


def test_yes_installs_missing_packages_without_asking(world: World) -> None:
    world.runner.tools.discard("pamu2fcfg")

    def install(_argv: list[str]) -> Completed:
        world.runner.tools.add("pamu2fcfg")
        return Completed(0)

    world.runner.on("apt-get", "install", result=install)
    world.setup(yes=True).prerequisites()
    assert world.runner.ran("apt-get") == [["apt-get", "install", "-y", "pamu2fcfg"]]


def test_declining_the_install_stops_with_the_command_to_run(world: World) -> None:
    (world.paths.at("/usr/lib/x86_64-linux-gnu/security/pam_u2f.so")).unlink()
    world.answer("")
    with pytest.raises(SetupError, match="sudo apt-get install libpam-u2f"):
        world.setup().prerequisites()
    assert world.runner.ran("apt-get") == []


def test_other_distributions_get_package_names_and_nothing_is_installed(world: World) -> None:
    world.paths.at("/etc/os-release").write_text('ID=fedora\nNAME="Fedora Linux"\n')
    world.runner.tools.discard("pamu2fcfg")
    with pytest.raises(SetupError, match="sudo dnf install pamu2fcfg"):
        world.setup(yes=True).prerequisites()
    assert world.runner.ran("apt-get") == []


@pytest.mark.parametrize(
    ("command", "output", "message"),
    [
        (("bluetoothd", "--version"), "5.64\n", "BlueZ 5.64 is too old"),
        (("systemctl", "--version"), "systemd 249 (249.11-0ubuntu3)\n", "systemd 249 is too old"),
    ],
)
def test_too_old_bluez_or_systemd_stops(
    world: World, command: tuple[str, ...], output: str, message: str
) -> None:
    world.runner.on(*command, result=Completed(0, output))
    with pytest.raises(SetupError, match=message):
        world.setup().prerequisites()


def test_uhid_is_loaded_when_missing(world: World) -> None:
    world.paths.uhid.unlink()
    world.setup().prerequisites()
    assert world.runner.ran("modprobe") == [["modprobe", "uhid"]]


def test_setup_needs_the_installed_service(world: World) -> None:
    world.paths.unit.unlink()
    with pytest.raises(SetupError, match=re.escape("sudo ./install.sh")):
        world.setup().prerequisites()


def test_a_stopped_bluetooth_service_is_reported(world: World) -> None:
    world.runner.on("systemctl", "is-active", "--quiet", "bluetooth", result=Completed(3))
    with pytest.raises(SetupError, match="systemctl enable --now bluetooth"):
        world.setup().prerequisites()


def test_without_an_adapter_setup_does_not_suggest_starting_bluetooth(world: World) -> None:
    # bluetooth.service needs /sys/class/bluetooth, so starting it would not help.
    world.runner.on("systemctl", "is-active", "--quiet", "bluetooth", result=Completed(3))
    (world.paths.bluetooth_class / "hci0").rmdir()
    with pytest.raises(SetupError, match="no Bluetooth adapter found"):
        world.setup().prerequisites()
    assert world.runner.ran("systemctl", "is-active", "--quiet", "bluetooth") == []


def test_only_hci_adapters_count_not_their_connections(tmp_path: Path) -> None:
    assert not has_bluetooth_adapter(tmp_path / "missing")
    (tmp_path / "hci0:3585").mkdir()
    assert not has_bluetooth_adapter(tmp_path)
    (tmp_path / "hci1").mkdir()
    assert has_bluetooth_adapter(tmp_path)


@pytest.mark.parametrize(
    ("os_release", "family"),
    [
        ("ID=ubuntu\nID_LIKE=debian\n", "debian"),
        ('ID="linuxmint"\nID_LIKE="ubuntu debian"\n', "debian"),
        ("ID=fedora\n", "fedora"),
        ("ID=arch\n", "arch"),
        ('ID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"\n', "suse"),
        ("ID=gentoo\n", None),
    ],
)
def test_distribution_families(os_release: str, family: str | None) -> None:
    assert distro_family(os_release) == family


def test_versions_are_read_from_tool_output() -> None:
    assert parse_version("systemd 255 (255.4-1ubuntu8)") == (255,)
    assert parse_version("5.72") == (5, 72)
    assert parse_version("") is None


@pytest.mark.parametrize(
    "failed",
    [
        Completed(127, "", "bluetoothd: error while loading shared libraries: libglib-2.0.so.0"),
        Completed(124, "", "/usr/libexec/bluetooth/bluetoothd: no answer within 60s"),
    ],
)
def test_a_failed_version_query_is_not_read_as_a_version(world: World, failed: Completed) -> None:
    world.runner.on("bluetoothd", "--version", result=failed)
    world.setup().prerequisites()
    assert "Could not tell the BlueZ version; going on." in world.console.text
    assert "OK: systemd 255, uhid," in world.console.text


def test_a_command_that_cannot_be_run_is_a_result_not_a_traceback(tmp_path: Path) -> None:
    tool = tmp_path / "bluetoothd"
    tool.write_text("#!/bin/sh\n")
    tool.chmod(0o644)
    result = SystemRunner().run([str(tool), "--version"])
    assert result.returncode == 126
    assert str(tool) in result.stderr


# Step 2: pairing


def test_an_already_bonded_key_is_not_paired_again(world: World) -> None:
    world.bluez.add_device(KEY, paired=True, bonded=True, trusted=True)
    world.answer("yes")
    setup = world.setup()
    assert setup.pair(config_for(KEY)) == KEY
    assert f'BlueZ already has a bond with {KEY}  "Test Key".' in world.console.text
    assert "already paired and bonded" in world.console.text
    assert not {"StartDiscovery", "Pair", "RegisterAgent", "RemoveDevice"} & set(
        world.bluez.members()
    )
    assert setup.changes == []


def test_a_bonded_key_that_is_not_trusted_gets_trusted(world: World) -> None:
    world.bluez.add_device(KEY, paired=True, bonded=True)
    world.answer("yes")
    setup = world.setup()
    assert setup.pair(config_for(KEY)) == KEY
    assert world.bluez.device(KEY)["Trusted"] is True
    assert "Pair" not in world.bluez.members()
    assert [change.undo for change in setup.changes] == [f"bluetoothctl untrust {KEY}"]


def test_a_new_key_is_found_paired_trusted_and_disconnected(world: World) -> None:
    world.answer("", "yes")
    setup = world.setup()
    assert setup.pair(None) == KEY
    assert f"Pair with {KEY}? Type yes to go on" in world.console.prompts[1]
    assert f'Found one device in pairing mode: {KEY}  "Test Key".' in world.console.text
    assert world.bluez.discovery_filter == {
        "Transport": "le",
        "UUIDs": ["0000fffd-0000-1000-8000-00805f9b34fb"],
    }
    members = world.bluez.members()
    assert members.index("StopDiscovery") < members.index("Pair")
    assert ("Disconnect", device_path(KEY)) in world.bluez.calls
    props = world.bluez.device(KEY)
    assert props["Paired"] and props["Bonded"] and props["Trusted"]
    assert [change.undo for change in setup.changes] == [f"bluetoothctl remove {KEY}"]
    assert "hold its button about 5 s until the LED blinks fast" in world.console.text
    assert setup.adapter is None  # only one adapter, so the config need not name it


@pytest.mark.parametrize("answer", ["", "y", "Y", "yes please"])
def test_a_lone_key_in_pairing_mode_is_only_paired_after_a_typed_yes(
    world: World, answer: str
) -> None:
    # Any device can advertise the FIDO service; whatever is paired gets registered next.
    world.answer("", answer)
    with pytest.raises(SetupError, match="no key was paired"):
        world.setup().pair(None)
    assert not {"Pair", "Set"} & set(world.bluez.members())
    assert not world.bluez.discovering
    assert world.console.answers == []


def test_a_given_address_is_paired_without_asking_which_key(world: World) -> None:
    world.answer("")
    assert world.setup(address=KEY).pair(None) == KEY
    assert world.console.answers == []
    # Still shown, so the user sees what is being paired.
    assert f'Found {KEY}  "Test Key", the address given with --address.' in world.console.text


def test_device_names_are_printed_harmlessly(world: World) -> None:
    # The name comes over the air: escape sequences could rewrite the screen or forge the list.
    world.bluez.add_device(KEY, name="\x1b[1A\x1b[2K\r    1) Your key\x1b]52;c;aGk=\x07")
    world.answer("", "")
    with pytest.raises(SetupError):
        world.setup().pair(None)
    text = world.console.text
    assert not {"\x1b", "\r", "\x07"} & set(text)
    assert f'{KEY}  "?[1A?[2K?    1) Your key?]52;c;aGk=?"' in text


def test_device_names_are_made_printable_and_short() -> None:
    assert device_name(None) == device_name("") == "(no name)"
    assert device_name("K33\u202e\n") == "K33??"
    assert device_name("\u00c4" * 60) == "\u00c4" * 40


def test_the_agent_is_registered_on_the_pairing_connection_and_removed_after(
    world: World,
) -> None:
    capabilities: list[str] = []
    original = world.bluez._Pair

    async def pair(path: str) -> None:
        capabilities.extend(world.bluez.agents.values())
        assert AGENT_PATH in world.bluez.exported
        await original(path)

    world.bluez._Pair = pair  # type: ignore[method-assign]
    world.answer("", "yes")
    world.setup().pair(None)
    assert capabilities == [AGENT_CAPABILITY] == ["KeyboardDisplay"]
    assert world.bluez.agents == {}
    assert world.bluez.exported == {}


def test_a_passkey_the_key_asks_for_is_typed_in_the_terminal(world: World) -> None:
    world.bluez.asks_passkey = True
    world.answer("", "yes", "012345")
    world.setup().pair(None)
    assert world.bluez.passkeys == [12345]
    assert world.console.answers == []


def test_a_key_with_a_resolvable_address_is_configured_with_its_identity_address(
    world: World,
) -> None:
    world.bluez.in_pairing_mode = {"4A:11:22:33:44:55"}
    world.bluez.identity["4A:11:22:33:44:55"] = "D1:22:33:44:55:66"
    world.answer("", "yes")
    setup = world.setup()
    assert setup.pair(None) == "D1:22:33:44:55:66"
    assert "identity" in world.console.text


def test_several_keys_in_pairing_mode_let_the_user_choose(world: World) -> None:
    world.bluez.in_pairing_mode.add("22:33:44:55:66:77")
    world.answer("", "2", "yes")
    assert world.setup().pair(None) == "22:33:44:55:66:77"
    assert world.bluez.calls.count(("Pair", device_path("22:33:44:55:66:77"))) == 1
    assert ("Pair", device_path(KEY)) not in world.bluez.calls


def test_no_key_in_pairing_mode_explains_what_to_check(world: World) -> None:
    world.bluez.in_pairing_mode = set()
    world.answer("")
    with pytest.raises(SetupError, match="connected to another"):
        world.setup().pair(None)
    assert "Pair" not in world.bluez.members()
    assert not world.bluez.discovering


def test_a_passkey_that_is_not_entered_cancels_the_pairing(world: World) -> None:
    world.bluez.asks_passkey = True
    world.answer("", "yes", "")
    with pytest.raises(SetupError, match="pairing was cancelled"):
        world.setup().pair(None)
    assert world.bluez.passkeys == []


def test_a_refused_pairing_says_what_to_do_and_removes_the_agent(world: World) -> None:
    world.bluez.pair_error = "org.bluez.Error.AuthenticationFailed"
    world.answer("", "yes")
    with pytest.raises(SetupError, match="refused the pairing"):
        world.setup().pair(None)
    assert world.bluez.agents == {}
    assert world.bluez.exported == {}
    assert world.bluez.disconnected


def test_a_pairing_that_hangs_is_cancelled(world: World) -> None:
    world.bluez.pair_hangs = True
    world.answer("", "yes")
    with pytest.raises(SetupError, match="did not finish pairing in time"):
        world.setup().pair(None)
    assert "CancelPairing" in world.bluez.members()
    assert world.bluez.agents == {}


def test_an_old_pairing_is_only_removed_after_asking(world: World) -> None:
    # BlueZ still has a bond, but the key is in pairing mode again (it was reset, say).
    world.bluez.add_device(KEY, paired=True, bonded=True, trusted=True)
    world.answer("2", "", "yes", "")  # pair a new key; Enter; that key; keep the old pairing
    with pytest.raises(SetupError, match=f"bluetoothctl remove {KEY}"):
        world.setup().pair(None)
    assert "RemoveDevice" not in world.bluez.members()
    assert world.console.answers == []


def test_an_old_pairing_is_replaced_when_the_user_agrees(world: World) -> None:
    world.bluez.add_device(KEY, paired=True, bonded=True, trusted=True)
    world.answer("2", "", "yes", "y")  # pair a new key; Enter; that key; remove the old one
    setup = world.setup()
    assert setup.pair(None) == KEY
    members = world.bluez.members()
    assert members.index("RemoveDevice") < members.index("Pair")
    assert world.bluez.device(KEY)["Bonded"] is True
    assert world.console.answers == []


def test_an_unfinished_pairing_of_the_configured_key_is_removed_after_asking(
    world: World,
) -> None:
    world.bluez.add_device(KEY, paired=True, bonded=False)
    world.answer("y", "", "yes")  # remove it; Enter once the key blinks; pair it
    assert world.setup().pair(config_for(KEY)) == KEY
    assert world.bluez.members().count("RemoveDevice") == 1
    assert world.bluez.device(KEY)["Bonded"] is True


def test_an_already_paired_key_can_be_picked_when_none_is_configured(world: World) -> None:
    world.bluez.add_device(KEY, paired=True, bonded=True, trusted=True)
    world.answer("1", "yes")
    assert world.setup().pair(config_for(PLACEHOLDER_ADDRESS)) == KEY
    assert "Pair" not in world.bluez.members()


def test_on_a_dual_boot_machine_pairing_waits_for_a_yes(world: World) -> None:
    (world.paths.root / "boot/efi/EFI/Microsoft").mkdir(parents=True)
    world.answer("")
    with pytest.raises(SetupError, match="copy it into BlueZ"):
        world.setup().pair(None)
    assert not {"Set", "StartDiscovery", "Pair"} & set(world.bluez.members())
    assert "also boots Windows" in world.console.text

    world.answer("y", "", "yes")
    assert world.setup().pair(None) == KEY


def test_a_switched_off_adapter_is_turned_on(world: World) -> None:
    world.bluez.objects["/org/bluez/hci0"]["org.bluez.Adapter1"]["Powered"] = False
    world.answer("", "yes")
    setup = world.setup()
    setup.pair(None)
    assert world.bluez.objects["/org/bluez/hci0"]["org.bluez.Adapter1"]["Powered"] is True
    assert "bluetoothctl power off" in [change.undo for change in setup.changes]


def test_a_blocked_adapter_points_at_rfkill(world: World) -> None:
    world.bluez.objects["/org/bluez/hci0"]["org.bluez.Adapter1"]["Powered"] = False
    world.bluez.power_error = "org.bluez.Error.Blocked"
    with pytest.raises(SetupError, match="rfkill unblock bluetooth"):
        world.setup().pair(None)


def test_an_already_bonded_key_on_a_switched_off_adapter_is_turned_on(world: World) -> None:
    # BlueZ lists bonded keys while the adapter is off; the key check would fail later.
    world.bluez.add_device(KEY, paired=True, bonded=True, trusted=True)
    world.bluez.objects["/org/bluez/hci0"][ADAPTER]["Powered"] = False
    world.answer("yes")
    setup = world.setup()
    assert setup.pair(config_for(KEY)) == KEY
    assert world.bluez.objects["/org/bluez/hci0"][ADAPTER]["Powered"] is True
    assert [change.undo for change in setup.changes] == ["bluetoothctl power off"]


def test_an_already_bonded_key_on_a_blocked_adapter_points_at_rfkill(world: World) -> None:
    world.bluez.add_device(KEY, paired=True, bonded=True, trusted=True)
    world.bluez.objects["/org/bluez/hci0"][ADAPTER]["Powered"] = False
    world.bluez.power_error = "org.bluez.Error.Blocked"
    world.answer("yes")
    with pytest.raises(SetupError, match="rfkill unblock bluetooth"):
        world.setup().pair(config_for(KEY))


def test_with_several_adapters_the_one_paired_on_is_written_to_the_config(world: World) -> None:
    # Unnamed, the bridge would take whichever powered adapter bleak lists first.
    world.bluez.objects["/org/bluez/hci1"] = {ADAPTER: {"Powered": False, "Pairable": True}}
    world.answer("", "yes")
    setup = world.setup()
    assert setup.pair(None) == KEY
    assert setup.adapter == "hci0"
    assert setup.configure(KEY, load_config(world.paths.config), adapter=setup.adapter)
    assert load_config(world.paths.config) == Config(address=KEY, adapter="hci0")
    assert setup.changes[-1].what.startswith(f'set address = "{KEY}" and adapter = "hci0"')


def test_bluez_not_running_is_explained(world: World) -> None:
    def not_running(path: str) -> None:
        raise DBusError("org.freedesktop.DBus.Error.ServiceUnknown", "unknown")

    world.bluez._GetManagedObjects = not_running  # type: ignore[assignment,method-assign]
    with pytest.raises(SetupError, match="BlueZ is not running"):
        world.setup().pair(None)


# Step 3: configuration


def test_the_address_is_written_with_comments_and_settings_kept(world: World) -> None:
    text = world.paths.config.read_text().replace("connect_timeout = 10", "connect_timeout = 7")
    world.paths.config.write_text(text)
    setup = world.setup()
    assert setup.configure(KEY, load_config(world.paths.config)) is True
    written = world.paths.config.read_text()
    assert written == text.replace(f'address = "{PLACEHOLDER_ADDRESS}"', f'address = "{KEY}"')
    assert load_config(world.paths.config).connect_timeout == 7
    assert stat.S_IMODE(world.paths.config.stat().st_mode) == 0o644
    assert setup.changes[0].undo.startswith(f'put back address = "{PLACEHOLDER_ADDRESS}"')


def test_the_config_is_left_alone_when_it_already_names_the_key(world: World) -> None:
    world.paths.config.write_text(f'address = "{KEY}"\n')
    before = world.paths.config.stat().st_mtime_ns
    setup = world.setup()
    assert setup.configure(KEY, load_config(world.paths.config)) is False
    assert world.paths.config.stat().st_mtime_ns == before
    assert setup.changes == []


def test_a_missing_config_is_created(world: World) -> None:
    world.paths.config.unlink()
    world.setup().configure(KEY, None)
    assert load_config(world.paths.config) == Config(address=KEY)


def test_a_config_that_would_end_up_wrong_is_never_written(world: World) -> None:
    # The first `address =` line is inside a multi-line string, so editing it would leave the
    # real address unchanged.
    text = f'device_name = """\naddress = "x"\n"""\naddress = "{PLACEHOLDER_ADDRESS}"\n'
    world.paths.config.write_text(text)
    with pytest.raises(SetupError, match="not writing"):
        world.setup().configure(KEY, load_config(world.paths.config))
    assert world.paths.config.read_text() == text


def test_an_invalid_config_stops_setup_before_anything_changes(world: World) -> None:
    world.paths.config.write_text('address = "nonsense"\n')
    world.answer()
    assert world.run() == 1
    assert "address must be a Bluetooth address" in world.console.text
    assert world.bluez.calls == []
    assert world.paths.config.read_text() == 'address = "nonsense"\n'


def test_set_address_adds_a_missing_address_line() -> None:
    assert set_address("idle_disconnect = 5\n", KEY) == f'address = "{KEY}"\nidle_disconnect = 5\n'


def test_set_adapter_replaces_the_line_or_adds_it_after_the_address() -> None:
    text = f'address = "{KEY}"\n# adapter = "hci0"\n'
    assert set_adapter(text, "hci1") == f'address = "{KEY}"\nadapter = "hci1"\n# adapter = "hci0"\n'
    assert set_adapter('adapter = "hci0"\n', "hci1") == 'adapter = "hci1"\n'


def test_the_adapter_is_written_even_when_the_address_is_already_set(world: World) -> None:
    world.paths.config.write_text(f'address = "{KEY}"\n')
    setup = world.setup()
    assert setup.configure(KEY, load_config(world.paths.config), adapter="hci1") is True
    assert load_config(world.paths.config) == Config(address=KEY, adapter="hci1")
    assert setup.changes[0].undo == f"delete the adapter line in {world.paths.config}"


def test_a_configured_adapter_is_left_alone(world: World) -> None:
    world.paths.config.write_text(f'address = "{KEY}"\nadapter = "hci1"\n')
    setup = world.setup()
    assert setup.configure(KEY, load_config(world.paths.config), adapter="hci1") is False
    assert setup.changes == []


# Step 3: the key's link

# A device settings file as BlueZ 5.72 writes one, with made-up keys.
BOND_INFO = """\
[General]
Name=FIDO2
AddressType=static
SupportedTechnologies=LE;
Trusted=true
Blocked=false
Services=00001800-0000-1000-8000-00805f9b34fb;0000fffd-0000-1000-8000-00805f9b34fb;

[LongTermKey]
Key=00112233445566778899AABBCCDDEEFF
Authenticated=0
EncSize=16
EDiv=0
Rand=0
"""
LINK_GROUP = "[ConnectionParameters]\nMinInterval=24\nMaxInterval=40\nLatency=0\nTimeout=500\n"


def bond_info(
    paths: Paths, text: str | None = BOND_INFO, adapter_dir: str = ADAPTER_ADDRESS
) -> Path:
    path = paths.at(f"/var/lib/bluetooth/{adapter_dir}/{KEY}/info")
    if text is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o600)
    return path


def paired_setup(world: World, *answers: str) -> Setup:
    """A Setup whose step 2 found the bonded key; `answers` follow the one step 2 asks."""
    world.bluez.add_device(KEY, paired=True, bonded=True, trusted=True)
    world.answer("yes", *answers)
    setup = world.setup()
    assert setup.pair(config_for(KEY)) == KEY
    return setup


def test_the_key_gets_a_longer_supervision_timeout_after_asking(world: World) -> None:
    world.answer("", "yes", "", "yes")
    assert world.run() == 0
    info = bond_info(world.paths)

    # Use the bonded key; allow 5 s (Enter); keep the registration; no backup key.
    world.answer("yes", "", "", "")
    assert world.run() == 0
    assert info.read_text() == BOND_INFO + "\n" + LINK_GROUP
    assert stat.S_IMODE(info.stat().st_mode) == 0o600
    # BlueZ reads the setting when it starts; the bridge follows BlueZ's restart.
    assert world.runner.ran("systemctl", "restart") == [
        ["systemctl", "restart", "bluetooth"],
        ["systemctl", "restart", "fido2-ble-bridge"],
    ]
    assert any("restart Bluetooth now?" in prompt for prompt in world.console.prompts)
    assert (
        f"undo: delete the [ConnectionParameters] group from {info}, then sudo systemctl "
        "restart bluetooth" in world.console.text
    )
    assert world.console.answers == []


def test_declining_leaves_the_settings_and_bluetooth_alone(world: World) -> None:
    info = bond_info(world.paths)
    setup = paired_setup(world, "n")
    assert setup.link(KEY) is False
    assert info.read_text() == BOND_INFO
    assert world.runner.ran("systemctl", "restart") == []
    assert setup.changes == []


def test_parameters_that_already_allow_the_timeout_are_kept_without_asking(world: World) -> None:
    text = BOND_INFO + "\n[ConnectionParameters]\nMinInterval=6\nMaxInterval=12\nLatency=4\n"
    info = bond_info(world.paths, text + "Timeout=600\n")
    setup = paired_setup(world)
    assert setup.link(KEY) is False
    assert info.read_text() == text + "Timeout=600\n"
    assert "already allow 5 s" in world.console.text
    assert world.runner.ran("systemctl", "restart") == []


def test_parameters_the_key_asked_for_are_replaced_and_their_undo_recorded(world: World) -> None:
    group = "[ConnectionParameters]\nMinInterval=12\nMaxInterval=24\nLatency=0\nTimeout=42\n"
    info = bond_info(world.paths, BOND_INFO + "\n" + group)
    setup = paired_setup(world, "y")
    assert setup.link(KEY) is True
    assert info.read_text() == BOND_INFO + "\n" + LINK_GROUP
    assert [change.undo for change in setup.changes] == [
        f"set [ConnectionParameters] in {info} back to MinInterval=12, MaxInterval=24, "
        "Latency=0, Timeout=42, then sudo systemctl restart bluetooth"
    ]


def test_without_bluez_settings_for_the_key_its_link_is_left_alone(world: World) -> None:
    setup = paired_setup(world)
    assert setup.link(KEY) is False
    assert "keep the default supervision timeout of 0.42 s" in world.console.text
    assert world.console.answers == []
    assert world.runner.ran("systemctl", "restart") == []


def test_an_adapter_with_a_static_address_keeps_its_settings_under_static(world: World) -> None:
    world.bluez.objects[ADAPTER_PATH]["org.bluez.Adapter1"]["AddressType"] = "random"
    info = bond_info(world.paths, adapter_dir=f"static-{ADAPTER_ADDRESS}")
    setup = paired_setup(world, "")
    assert setup.bond_file == info
    assert setup.link(KEY) is True
    assert info.read_text().endswith(LINK_GROUP)


def test_a_failed_bluetooth_restart_says_how_to_apply_the_setting(world: World) -> None:
    world.runner.on("systemctl", "restart", "bluetooth", result=Completed(1, "", "Failed.\n"))
    info = bond_info(world.paths)
    setup = paired_setup(world, "")
    with pytest.raises(SetupError, match="takes effect once Bluetooth restarts"):
        setup.link(KEY)
    assert info.read_text().endswith(LINK_GROUP)
    assert len(setup.changes) == 1


def test_bluez_that_does_not_list_the_key_again_stops_setup(world: World) -> None:
    bond_info(world.paths)
    setup = paired_setup(world, "")
    setup.timing = dataclasses.replace(FAST, bluetooth=0.05)

    def restart_without_the_key(_argv: list[str]) -> Completed:
        del world.bluez.objects[device_path(KEY)]
        return Completed(0)

    world.runner.on("systemctl", "restart", "bluetooth", result=restart_without_the_key)
    with pytest.raises(SetupError, match="did not list the key again"):
        setup.link(KEY)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", LINK_GROUP),
        ("[General]\nName=K\n", "[General]\nName=K\n\n" + LINK_GROUP),
        ("[General]\nName=K", "[General]\nName=K\n\n" + LINK_GROUP),
        # A header at the end of the file without a newline.
        ("[General]\nName=K\n[ConnectionParameters]", "[General]\nName=K\n" + LINK_GROUP),
        # Other entries and comments in the group stay; every copy of ours goes.
        (
            "[ConnectionParameters]\n# kept\nTimeout=1\nOther=x\nTimeout=2\n\n"
            "[LongTermKey]\nKey=0\n",
            LINK_GROUP + "# kept\nOther=x\n\n[LongTermKey]\nKey=0\n",
        ),
        # Values BlueZ reads as 0 (not numbers) and a group the kernel would ignore.
        (
            "[ConnectionParameters]\nMinInterval=x\nMaxInterval=40\nLatency=0\nTimeout=500\n",
            LINK_GROUP,
        ),
        (
            "[ConnectionParameters]\nMinInterval=24\nMaxInterval=40\nLatency=60\nTimeout=500\n",
            LINK_GROUP,
        ),
    ],
)
def test_link_parameters_change_only_their_group(text: str, expected: str) -> None:
    assert with_link_parameters(text) == expected


def test_usable_link_parameters_are_left_as_they_are() -> None:
    assert with_link_parameters(LINK_GROUP) is None
    assert with_link_parameters("[A]\n" + LINK_GROUP.replace("500", "3200") + "[B]\n") is None


@pytest.mark.parametrize(
    ("parameters", "valid"),
    [
        ((24, 40, 0, 500), True),
        ((24, 40, 0, 42), True),
        ((5, 40, 0, 500), False),  # interval below 7.5 ms
        ((41, 40, 0, 500), False),  # min above max
        ((24, 3201, 0, 3200), False),  # interval above 4 s
        ((24, 40, 0, 9), False),  # timeout below 100 ms
        ((24, 40, 0, 3201), False),  # timeout above 32 s
        ((24, 400, 0, 50), False),  # timeout not above twice the interval
        ((24, 40, 49, 500), True),
        ((24, 40, 50, 500), False),  # latency the timeout cannot cover
        ((24, 24, 500, 3200), False),  # latency above 499
    ],
)
def test_link_parameters_are_checked_as_the_kernel_checks_them(
    parameters: tuple[int, int, int, int], valid: bool
) -> None:
    assert valid_link_parameters(*parameters) is valid


# Step 4: service and key check


def test_the_service_is_enabled_and_started_then_the_key_is_checked(world: World) -> None:
    setup = world.setup()
    setup.service(Config(address=KEY), config_changed=True)
    assert world.runner.ran("systemctl", "enable") == [
        ["systemctl", "enable", "--now", "fido2-ble-bridge"]
    ]
    assert world.runner.ran("systemctl", "restart") == []
    # The configured connect timeout, or longer, to give the user time to wake the key.
    assert world.checks == [(Config(address=KEY), max(Config.connect_timeout, FAST.wake))]
    assert "Wake the key now: press its button once." in world.console.text


def test_a_running_service_is_restarted_for_a_new_address(world: World) -> None:
    world.state.service_enabled = world.state.service_active = True
    world.setup().service(Config(address=KEY), config_changed=True)
    assert world.runner.ran("systemctl", "restart") == [
        ["systemctl", "restart", "fido2-ble-bridge"]
    ]
    assert world.runner.ran("systemctl", "enable") == []


def test_a_running_service_with_an_unchanged_address_is_left_alone(world: World) -> None:
    world.state.service_enabled = world.state.service_active = True
    setup = world.setup()
    setup.service(Config(address=KEY), config_changed=False)
    assert [argv[1] for argv in world.runner.ran("systemctl")] == ["is-enabled", "is-active"]
    assert setup.changes == []


def test_a_failing_systemctl_points_at_the_journal(world: World) -> None:
    world.runner.on("systemctl", "enable", result=Completed(1, "", "Unit not found.\n"))
    with pytest.raises(SetupError, match="journalctl -u fido2-ble-bridge"):
        world.setup().service(Config(address=KEY), config_changed=True)


@pytest.mark.parametrize(
    ("error", "advice"),
    [
        (KeyNotReachable("did not advertise within 30s"), "not connected to another device"),
        (KeyNotTrusted("not bonded"), f"bluetoothctl remove {KEY}"),
    ],
)
def test_a_failed_key_check_says_what_to_do(
    world: World, error: KeyNotReachable | KeyNotTrusted, advice: str
) -> None:
    world.check_result = CheckResult(False, str(error), error)
    with pytest.raises(SetupError, match=advice):
        world.setup().service(Config(address=KEY), config_changed=False)


def test_the_check_runs_the_real_getinfo_over_the_ble_link(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        daemon, "BleakGattConnector", lambda _address, _adapter=None: SimulatedConnector()
    )
    host = dataclasses.replace(world.host(), check=Host(console=world.console).check)
    Setup(SetupOptions(), host).service(Config(address=KEY), config_changed=False)
    assert "OK: bonded and encrypted link, FIDO2 selected" in world.console.text


# Step 5: fingerprint


def test_a_key_with_an_enrolled_fingerprint_is_ready(world: World) -> None:
    assert world.setup().fingerprint(Config(address=KEY)) == NODE
    assert world.runner.ran("fido2-token") == [["fido2-token", "-L"], ["fido2-token", "-I", NODE]]
    assert "A fingerprint is enrolled" in world.console.text


def test_without_a_fingerprint_setup_offers_enrollment(world: World) -> None:
    infos = [token_info("rk, up, nouv, clientPin"), token_info("rk, up, uv, clientPin")]
    world.runner.on("fido2-token", "-I", result=lambda _argv: Completed(0, infos.pop(0)))
    world.runner.on("fido2-token", "-S", "-e", result=Completed(0))
    world.answer("y")
    setup = world.setup()
    assert setup.fingerprint(Config(address=KEY)) == NODE
    enroll = world.runner.calls.index(["fido2-token", "-S", "-e", NODE])
    assert world.runner.options[enroll]["interactive"]
    assert "fido2-token -D -e" in setup.changes[0].undo


def test_declining_enrollment_stops_with_the_command(world: World) -> None:
    world.runner.on("fido2-token", "-I", result=Completed(0, token_info("rk, up, nouv, clientPin")))
    world.answer("")
    with pytest.raises(SetupError, match=f"fido2-token -S -e {NODE}"):
        world.setup().fingerprint(Config(address=KEY))
    assert world.runner.ran("fido2-token", "-S") == []


def test_enrollment_without_a_pin_offers_to_set_one_first(world: World) -> None:
    infos = [token_info("rk, up, noclientPin"), token_info("rk, up, uv, clientPin")]
    world.runner.on("fido2-token", "-I", result=lambda _argv: Completed(0, infos.pop(0)))
    world.runner.on("fido2-token", "-S", result=Completed(0))
    world.answer("y", "y")
    setup = world.setup()
    assert setup.fingerprint(Config(address=KEY)) == NODE
    assert world.runner.ran("fido2-token", "-S") == [
        ["fido2-token", "-S", NODE],
        ["fido2-token", "-S", "-e", NODE],
    ]
    assert [change.what for change in setup.changes] == [
        "set a PIN on the key",
        "enrolled a fingerprint on the key",
    ]


def test_declining_to_set_a_pin_stops_with_the_command(world: World) -> None:
    world.runner.on("fido2-token", "-I", result=Completed(0, token_info("rk, up, noclientPin")))
    world.answer("")
    with pytest.raises(SetupError, match=f"fido2-token -S {NODE}"):
        world.setup().fingerprint(Config(address=KEY))
    assert world.runner.ran("fido2-token", "-S") == []


def test_a_sleeping_key_that_answers_without_ctap2_is_reported(world: World) -> None:
    world.runner.on("fido2-token", "-I", result=Completed(0, "proto: 0x02\nmajor: 0x01\n"))
    with pytest.raises(SetupError, match="Wake the key"):
        world.setup().fingerprint(Config(address=KEY))


def test_a_missing_virtual_device_points_at_the_journal(world: World) -> None:
    with pytest.raises(SetupError, match="journalctl"):
        world.setup().fingerprint(Config(address=KEY, device_name="other name"))


def test_only_the_uhid_device_counts_as_the_bridge(tmp_path: Path) -> None:
    add_hidraw(tmp_path, "FIDO2 BLE bridge", 3, virtual=False)
    hidraw = tmp_path / "sys/class/hidraw"
    assert find_hidraw_node(hidraw, "FIDO2 BLE bridge") is None
    add_hidraw(tmp_path, "FIDO2 BLE bridge", 7)
    assert find_hidraw_node(hidraw, "FIDO2 BLE bridge") == "/dev/hidraw7"


def test_token_options_are_parsed() -> None:
    assert parse_options(token_info("rk, up, uv, noplat")) == {"rk", "up", "uv", "noplat"}
    assert parse_options("proto: 0x02\n") is None


# Step 6: registration


def test_registering_writes_the_users_line_once_the_test_passed(world: World) -> None:
    bob = "bob:Qm9i,S2V5,es256,+presence\n"
    world.paths.mappings.write_text(bob)
    world.answer("")
    setup = world.setup()
    assert setup.register(NODE, BRIDGE) == NODE
    assert setup.registered
    assert world.paths.mappings.read_text() == bob  # nothing is saved before the test
    pamu2fcfg = world.runner.calls.index(PAMU2FCFG)
    assert world.runner.options[pamu2fcfg]["interactive"]
    assert "It must be your own key that lights up" in world.console.text
    assert setup.test_login(NODE) is True
    assert world.paths.mappings.read_text() == f"{bob}{MAPPING}\n"
    # Tested on exactly the text that was then saved.
    assert world.pam.authfiles == [f"{bob}{MAPPING}\n"]


def test_an_existing_registration_is_kept_unless_replacing_is_confirmed(world: World) -> None:
    world.paths.mappings.write_text(f"{USER}:T2xk,S2V5,es256,+presence+verification\n")
    world.answer("", "")
    setup = world.setup()
    setup.register(NODE, BRIDGE)
    assert world.runner.ran("pamu2fcfg") == []
    assert world.paths.mappings.read_text() == f"{USER}:T2xk,S2V5,es256,+presence+verification\n"
    assert not setup.registered


def test_replacing_a_registration_keeps_a_backup(world: World) -> None:
    old = f"{USER}:T2xk,S2V5,es256,+presence+verification\n"
    world.paths.mappings.write_text(old)
    world.answer("y", "")
    setup = world.setup()
    setup.register(NODE, BRIDGE)
    assert (
        "replacing that line and the 1 key(s) on it (backup keys too)?"
        in (world.console.prompts[0])
    )
    assert world.paths.mappings.read_text() == old
    assert setup.test_login(NODE) is True
    assert world.paths.mappings.read_text() == MAPPING + "\n"
    backup = world.paths.mappings.with_name("u2f_mappings.bak")
    assert backup.read_text() == old
    assert setup.changes[0].undo == f"sudo cp {backup} {world.paths.mappings}"


def test_registration_refuses_while_other_fido_devices_are_attached(world: World) -> None:
    world.state.devices = ["/dev/hidraw2", NODE]
    world.answer("")  # Enter, without unplugging anything
    with pytest.raises(SetupError, match="still attached"):
        world.setup().register(NODE, BRIDGE)
    assert world.runner.ran("pamu2fcfg") == []
    assert not world.paths.mappings.exists()


def test_a_failed_registration_is_not_retried_and_writes_nothing(world: World) -> None:
    world.runner.on("pamu2fcfg", result=Completed(1, "", "error: fido_dev_make_cred\n"))
    with pytest.raises(SetupError, match="which finger is enrolled"):
        world.setup().register(NODE, BRIDGE)
    assert len(world.runner.ran("pamu2fcfg")) == 1
    assert not world.paths.mappings.exists()


def test_unexpected_pamu2fcfg_output_is_not_written(world: World) -> None:
    world.runner.on("pamu2fcfg", result=Completed(0, "bob:something else"))
    with pytest.raises(SetupError, match="unexpected"):
        world.setup().register(NODE, BRIDGE)
    assert not world.paths.mappings.exists()


BACKUP_ENTRY = ":QmFja3Vw,S2V5Mg==,es256,+presence+verification"


def plug_in_a_backup_key(world: World, *, unplugged_after: bool = True) -> None:
    """While the bridge is stopped, only the backup key is attached."""
    world.runner.on(
        "pamu2fcfg", result=lambda argv: Completed(0, BACKUP_ENTRY if "-n" in argv else MAPPING)
    )

    def stop(_argv: list[str]) -> Completed:
        world.state.devices = ["/dev/hidraw2"]
        return Completed(0)

    def start(_argv: list[str]) -> Completed:
        world.state.devices = [NODE] if unplugged_after else ["/dev/hidraw2", NODE]
        return Completed(0)

    world.runner.on("systemctl", "stop", "fido2-ble-bridge", result=stop)
    world.runner.on("systemctl", "start", "fido2-ble-bridge", result=start)


def test_a_backup_key_is_added_to_the_users_line(world: World) -> None:
    plug_in_a_backup_key(world)
    world.answer("y", "")  # yes, a backup key; Enter once it is plugged in
    setup = world.setup()
    assert setup.register(NODE, BRIDGE) == NODE
    assert world.runner.ran("pamu2fcfg")[1] == [*PAMU2FCFG, "-n"]
    assert world.runner.ran("fido2-token", "-I") == [["fido2-token", "-I", "/dev/hidraw2"]]
    assert world.runner.ran("systemctl", "start") == [["systemctl", "start", "fido2-ble-bridge"]]
    assert not world.paths.mappings.exists()
    assert setup.test_login(NODE) is True
    assert world.paths.mappings.read_text() == MAPPING + BACKUP_ENTRY + "\n"
    # Tested on exactly the text that was then saved. The bridge was the only FIDO device
    # attached (fido2-token -L), so the backup key could not pass the test for it.
    assert world.pam.authfiles == [MAPPING + BACKUP_ENTRY + "\n"]
    assert world.runner.ran("fido2-token", "-L")[-1] == ["fido2-token", "-L"]
    assert [change.what for change in setup.changes] == [
        f"registered the key and a backup key for {USER} in {world.paths.mappings}"
    ]


def test_a_backup_key_without_a_fingerprint_is_not_registered(world: World) -> None:
    # The PAM line requires the key to verify a fingerprint itself; a PIN-only key could not
    # log in with it.
    plug_in_a_backup_key(world)
    world.runner.on("fido2-token", "-I", "/dev/hidraw2", result=Completed(0, token_info("rk, up")))
    world.answer("y", "")
    setup = world.setup()
    setup.register(NODE, BRIDGE)
    assert world.runner.ran("pamu2fcfg") == [PAMU2FCFG]
    assert "no enrolled fingerprint" in world.console.text
    assert setup.backup_entries == []


def test_the_login_test_waits_until_the_backup_key_is_unplugged(world: World) -> None:
    plug_in_a_backup_key(world, unplugged_after=False)
    world.answer("y", "", "")  # a backup key; Enter once plugged in; Enter without unplugging
    setup = world.setup()
    node = setup.register(NODE, BRIDGE)
    with pytest.raises(SetupError, match="still attached"):
        setup.test_login(node)
    assert "The login test must use the Bluetooth key alone" in world.console.text
    assert world.pam.calls == []
    assert not world.paths.mappings.exists()


def test_a_backup_key_for_a_kept_registration_is_saved_without_a_test(world: World) -> None:
    old = f"{USER}:T2xk,S2V5,es256,+presence+verification"
    world.paths.mappings.write_text(old + "\n")
    world.paths.common_auth.write_text(PAM_ENABLED)
    plug_in_a_backup_key(world)
    world.answer("", "y", "")  # keep the registration; a backup key; Enter once plugged in
    setup = world.setup()
    assert setup.test_login(setup.register(NODE, BRIDGE)) is False
    assert world.pam.calls == []
    assert world.paths.mappings.read_text() == old + BACKUP_ENTRY + "\n"


def test_merging_mappings() -> None:
    text = "bob:B\nalice:A1\n"
    assert merge_mapping(text, "alice", "alice:A2") == "bob:B\nalice:A2\n"
    assert merge_mapping(text, "alice", ":A2", append=True) == "bob:B\nalice:A1:A2\n"
    assert merge_mapping("", "carol", "carol:C") == "carol:C\n"


# Step 7: login test


def registered(world: World) -> Setup:
    """A Setup right after step 6 registered the key."""
    setup = world.setup()
    setup.registered = True
    setup.new_entry = MAPPING
    return setup


def test_a_failed_login_test_runs_once_and_saves_nothing(world: World) -> None:
    world.pam.succeeds = False
    setup = registered(world)
    with pytest.raises(SetupError, match="Nothing was saved"):
        setup.test_login(NODE)
    assert len(world.pam.calls) == 1
    assert world.runner.ran("pam-auth-update") == []
    assert not world.paths.mappings.exists()
    assert setup.changes == []


def test_a_failed_login_test_leaves_a_working_registration_in_place(world: World) -> None:
    # With PAM enabled, a replaced line would be live at once: it is only saved once it worked.
    old = f"{USER}:T2xk,S2V5,es256,+presence+verification:QmFja3Vw,S2V5Mg==,es256,+presence\n"
    world.paths.mappings.write_text(old)
    world.paths.common_auth.write_text(PAM_ENABLED)
    world.pam.succeeds = False
    world.answer("y", "")  # replace the line; no backup key
    setup = world.setup()
    setup.register(NODE, BRIDGE)
    with pytest.raises(SetupError, match="are as they were"):
        setup.test_login(NODE)
    assert world.paths.mappings.read_text() == old
    assert not world.paths.mappings.with_name("u2f_mappings.bak").exists()


def test_the_login_test_shows_pam_u2f_messages(world: World) -> None:
    assert registered(world).test_login(NODE) is True
    assert "pam_u2f: Please touch the device." in world.console.text


def test_the_login_test_runs_with_the_bridge_as_the_only_fido_device(world: World) -> None:
    world.state.devices = ["/dev/hidraw2", NODE]
    world.answer("")  # Enter, without unplugging anything
    with pytest.raises(SetupError, match="still attached"):
        registered(world).test_login(NODE)
    assert world.pam.calls == []


def test_a_kept_registration_is_tested_as_it_is(world: World) -> None:
    old = f"{USER}:T2xk,S2V5,es256,+presence+verification"
    world.paths.mappings.write_text(old + "\n")
    assert world.setup().test_login(NODE) is True
    assert world.pam.authfiles == [old + "\n"]


def test_without_pam_start_confdir_the_test_is_left_to_the_user(world: World) -> None:
    world.pam.is_available = False
    setup = registered(world)
    assert setup.test_login(NODE) is False
    assert "pamtester" in world.console.text
    assert world.pam.calls == []
    assert world.paths.mappings.read_text() == MAPPING + "\n"


def test_no_fingerprint_is_asked_for_when_nothing_changed_and_pam_is_enabled(
    world: World,
) -> None:
    world.paths.common_auth.write_text(PAM_ENABLED)
    assert world.setup().test_login(NODE) is False
    assert world.pam.calls == []


# Step 8: enabling PAM


def after_the_login_test(world: World) -> Setup:
    """A Setup right after step 7's login test passed with the installed profile's line."""
    setup = world.setup()
    setup.tested_profile = world.paths.pam_profile.read_text()
    return setup


def test_pam_is_only_enabled_after_typing_yes(world: World) -> None:
    world.answer("y")
    after_the_login_test(world).enable_pam(tested=True)
    assert world.runner.ran("pam-auth-update") == []
    assert "Not enabled" in world.console.text


def test_pam_is_never_enabled_without_a_passing_test(world: World) -> None:
    world.setup().enable_pam(tested=False)
    assert world.runner.ran("pam-auth-update") == []


def test_a_refused_pam_auth_update_is_reported_and_never_forced(world: World) -> None:
    world.state.pam_auth_update_works = False
    world.answer("yes")
    with pytest.raises(SetupError, match="Local modifications"):
        after_the_login_test(world).enable_pam(tested=True)
    assert world.runner.ran("pam-auth-update") == [
        ["pam-auth-update", "--enable", "fido2-ble-bridge"]
    ]


def test_without_pam_auth_update_the_line_is_printed_not_written(world: World) -> None:
    world.runner.tools.discard("pam-auth-update")
    before = world.paths.common_auth.read_text()
    world.setup().enable_pam(tested=True)
    assert (
        "auth sufficient pam_u2f.so authfile=/etc/fido2-ble-bridge/u2f_mappings "
        f"origin={ORIGIN} cue userverification=1"
    ) in world.console.text
    assert world.paths.common_auth.read_text() == before
    assert world.runner.calls == []


def test_no_pam_skips_enabling(world: World) -> None:
    world.setup(no_pam=True).enable_pam(tested=True)
    assert world.runner.ran("pam-auth-update") == []
    assert "Skipped (--no-pam)" in world.console.text


def test_a_failure_midway_lists_what_was_changed_so_far(world: World) -> None:
    world.pam.succeeds = False
    world.answer("", "yes", "")
    assert world.run() == 1
    text = world.console.text
    assert "Stopped: the login test failed" in text
    assert f"undo: bluetoothctl remove {KEY}" in text
    assert "pam-auth-update --disable" not in text
    assert "u2f_mappings" not in text.split("\nSummary\n", 1)[1]
    assert not world.paths.mappings.exists()


# Security review: a device someone else paired, or one waiting at the key's address (M2)


def test_a_configured_key_whose_pairing_is_gone_is_paired_again_only_after_a_typed_yes(
    world: World,
) -> None:
    # Any local user may remove the pairing (BlueZ's default D-Bus policy), and a device that
    # copies the key's address can then wait in pairing mode for the next setup run.
    world.answer("", "")  # Enter once the key blinks; then no typed yes
    with pytest.raises(SetupError, match="no key was paired"):
        world.setup().pair(config_for(KEY))
    assert "Pair" not in world.bluez.members()
    text = world.console.text
    assert f"the configured key {KEY} is not paired with this computer" in text
    assert "BlueZ lets every local user remove pairings" in text
    assert f'Found one device in pairing mode: {KEY}  "Test Key".' in text

    world.answer("", "yes")
    assert world.setup().pair(config_for(KEY)) == KEY
    assert ("Pair", device_path(KEY)) in world.bluez.calls


def test_a_device_bonded_by_someone_else_is_not_used_without_a_typed_yes(world: World) -> None:
    rogue = "C0:FF:EE:00:00:01"
    world.bluez.in_pairing_mode = set()
    world.bluez.add_device(rogue, paired=True, bonded=True, name="K33 Fingerprint Key")
    world.answer("1", "")  # pick it from the list; Enter is not a yes
    setup = world.setup()
    with pytest.raises(SetupError, match=f"bluetoothctl remove {rogue}"):
        setup.pair(None)
    assert "A bond alone does not prove that it is your key" in world.console.text
    assert world.bluez.device(rogue)["Trusted"] is False
    assert setup.changes == []


def test_the_configured_bonded_key_is_shown_and_must_be_confirmed(world: World) -> None:
    world.bluez.add_device(KEY, paired=True, bonded=True, trusted=True)
    world.answer("y")
    with pytest.raises(SetupError, match="was not used"):
        world.setup().pair(config_for(KEY))
    assert f'BlueZ already has a bond with {KEY}  "Test Key".' in world.console.text


def test_a_bonded_key_named_with_address_is_shown_without_a_question(world: World) -> None:
    world.bluez.add_device(KEY, paired=True, bonded=True, trusted=True)
    assert world.setup(address=KEY).pair(None) == KEY
    assert f'Using {KEY}  "Test Key", which BlueZ already has a bond with.' in world.console.text
    assert world.console.prompts == []


# Security review: the authfile line pam_u2f really uses (M3)


def test_authfile_lines_are_read_as_pam_u2f_reads_them() -> None:
    text = "bob:B\nalice:A1:A2\n::alice:A3\nalicex:X\nalice\n"
    # pam_u2f splits with strtok, which skips empty fields, and keeps the last line it matched.
    assert mapping_lines(text, "alice") == ["alice:A1:A2", "::alice:A3", "alice"]
    assert mapping_line(text, "alice") == "alice"
    assert credential_count("alice:A1:A2") == 2
    assert credential_count("alice::A1") == 1
    assert credential_count("alice") == 0


def test_replacing_a_registration_removes_every_line_of_the_user() -> None:
    text = "alice:OLD1\nbob:B\nalice:OLD2\n"
    assert merge_mapping(text, "alice", "alice:NEW") == "alice:NEW\nbob:B\n"


def test_a_backup_key_goes_on_the_line_pam_u2f_uses() -> None:
    text = "alice:OLD1\nbob:B\nalice:OLD2\n"
    expected = "alice:OLD1\nbob:B\nalice:OLD2:BACKUP\n"
    assert merge_mapping(text, "alice", ":BACKUP", append=True) == expected


def test_registering_over_duplicate_lines_leaves_one_line_tested_as_saved(world: World) -> None:
    old1 = f"{USER}:T2xkMQ==,S2V5,es256,+presence+verification"
    old2 = f"{USER}:T2xkMg==,S2V5,es256,+presence+verification:QmFr,S2V5,es256,+presence"
    bob = "bob:Qm9i,S2V5,es256,+presence"
    world.paths.mappings.write_text(f"{old1}\n{bob}\n{old2}\n")
    world.answer("y", "")  # replace; no backup key
    setup = world.setup()
    setup.register(NODE, BRIDGE)
    assert f"{USER} has 2 lines in {world.paths.mappings}" in world.console.text
    assert "the last one, which has 2 key(s)" in world.console.text
    assert "replacing all 2 lines and the 2 key(s) on it" in world.console.prompts[0]
    assert setup.test_login(NODE) is True
    saved = world.paths.mappings.read_text()
    assert saved == f"{MAPPING}\n{bob}\n"
    assert world.pam.authfiles == [saved]


def test_a_backup_key_for_a_kept_registration_goes_on_the_line_that_counts(
    world: World,
) -> None:
    old1 = f"{USER}:T2xkMQ==,S2V5,es256,+presence+verification"
    old2 = f"{USER}:T2xkMg==,S2V5,es256,+presence+verification"
    world.paths.mappings.write_text(f"{old1}\n{old2}\n")
    plug_in_a_backup_key(world)
    world.answer("", "y", "")  # keep the registration; a backup key; Enter once plugged in
    setup = world.setup()
    assert setup.test_login(setup.register(NODE, BRIDGE)) is True
    saved = world.paths.mappings.read_text()
    assert saved == f"{old1}\n{old2}{BACKUP_ENTRY}\n"
    assert world.pam.authfiles == [saved]


def test_an_authfile_changed_during_the_test_is_not_overwritten(world: World) -> None:
    edited = "bob:Qm9i,S2V5,es256,+presence\n"
    authenticate = world.pam.authenticate

    def edited_meanwhile(*args: Any) -> PamResult:
        world.paths.mappings.write_text(edited)
        return authenticate(*args)

    world.pam.authenticate = edited_meanwhile  # type: ignore[method-assign,assignment]
    with pytest.raises(SetupError, match="changed while the login test ran"):
        registered(world).test_login(NODE)
    assert world.paths.mappings.read_text() == edited


# Security review: finding the bridge's own device (L5)


def test_a_bluetooth_hid_device_named_like_the_bridge_is_not_the_bridge(tmp_path: Path) -> None:
    # BlueZ makes uhid devices for BLE keyboards and the like (HID over GATT), on the Bluetooth
    # bus and named whatever the remote device calls itself.
    hidraw = tmp_path / "sys/class/hidraw"
    add_hidraw(tmp_path, BRIDGE, 10, bus="0005", phys="00:1a:7d:da:71:13", uniq="c0:ff:ee:00:01")
    assert find_hidraw_node(hidraw, BRIDGE) is None
    add_hidraw(tmp_path, BRIDGE, 3)
    assert find_hidraw_node(hidraw, BRIDGE) == "/dev/hidraw3"


def test_a_uhid_device_without_the_bridge_s_phys_is_not_the_bridge(tmp_path: Path) -> None:
    add_hidraw(tmp_path, BRIDGE, 4, phys="")
    assert find_hidraw_node(tmp_path / "sys/class/hidraw", BRIDGE) is None


def test_lookalike_devices_are_sorted_by_number_and_never_guessed_between(tmp_path: Path) -> None:
    hidraw = tmp_path / "sys/class/hidraw"
    add_hidraw(tmp_path, BRIDGE, 10)
    add_hidraw(tmp_path, BRIDGE, 3)
    assert find_hidraw_nodes(hidraw, BRIDGE) == ["/dev/hidraw3", "/dev/hidraw10"]
    with pytest.raises(AmbiguousDevice):
        find_hidraw_node(hidraw, BRIDGE)


def test_two_lookalike_devices_stop_step_5_before_anything_is_sent(world: World) -> None:
    add_hidraw(world.paths.root, BRIDGE, 9)
    with pytest.raises(SetupError, match="all look like the bridge's device"):
        world.setup().fingerprint(Config(address=KEY))
    assert world.runner.ran("fido2-token") == []


def test_step_5_sends_nothing_to_a_node_libfido2_does_not_list(world: World) -> None:
    world.state.devices = []
    # A key without a PIN: step 5 would offer to set one on this node.
    world.runner.on("fido2-token", "-I", result=Completed(0, token_info("rk, up, noclientPin")))
    with pytest.raises(SetupError, match="does not list it as a FIDO device"):
        world.setup().fingerprint(Config(address=KEY))
    assert world.runner.ran("fido2-token") == [["fido2-token", "-L"]]


# Security review: the profile step 8 enables is the one step 7 tested (L6)


def edit_profile(world: World, old: str, new: str) -> None:
    profile = world.paths.pam_profile
    text = profile.read_text()
    assert old in text
    profile.write_text(text.replace(old, new))


@pytest.mark.parametrize(
    ("old", "new", "problem"),
    [
        ("cue userverification=1", "cue userverification=1 nouserok", "nouserok"),
        ("cue userverification=1", "cue userverification=1 alwaysok", "alwaysok"),
        ("cue userverification=1", "cue openasuser userverification=1", "openasuser"),
        (" userverification=1", "", "no userverification=1"),
        ("authfile=/etc/fido2-ble-bridge/", "authfile=/home/alice/.config/", "authfile is not"),
    ],
)
def test_a_weakened_profile_is_neither_tested_nor_enabled(
    world: World, old: str, new: str, problem: str
) -> None:
    edit_profile(world, old, new)
    setup = registered(world)
    with pytest.raises(SetupError, match=re.escape(problem)):
        setup.test_login(NODE)
    assert world.pam.calls == []  # no fingerprint was asked for
    assert not world.paths.mappings.exists()
    world.answer("yes")
    with pytest.raises(SetupError, match=re.escape(problem)):
        setup.enable_pam(tested=True)
    assert world.runner.ran("pam-auth-update") == []


def test_the_login_test_uses_the_installed_profile_s_own_pam_u2f_line(world: World) -> None:
    edit_profile(world, "cue userverification=1", "cue max_devices=3 userverification=1")
    assert registered(world).test_login(NODE) is True
    ((_service, _user, stack),) = world.pam.calls
    assert re.fullmatch(
        rf"auth required pam_u2f\.so authfile=\S+/u2f_mappings origin={re.escape(ORIGIN)} cue "
        r"max_devices=3 userverification=1\n",
        stack,
    )


def test_a_profile_changed_after_the_test_is_not_enabled(world: World) -> None:
    setup = registered(world)
    assert setup.test_login(NODE) is True
    # Harmless in itself, but not the line that was tested.
    edit_profile(world, "cue userverification=1", "cue max_devices=3 userverification=1")
    world.answer("yes")
    with pytest.raises(SetupError, match="not the profile whose pam_u2f line the login test"):
        setup.enable_pam(tested=True)
    assert world.runner.ran("pam-auth-update") == []


def test_a_profile_whose_auth_blocks_differ_is_refused(world: World) -> None:
    profile = world.paths.pam_profile
    head, initial = profile.read_text().split("Auth-Initial:\n")
    profile.write_text(f"{head}Auth-Initial:\n{initial.replace('cue ', 'cue nouserok ')}")
    with pytest.raises(SetupError, match="2 different ones"):
        registered(world).test_login(NODE)
    assert world.pam.calls == []


def test_pam_u2f_s_own_config_file_is_checked_too(world: World) -> None:
    world.paths.pam_u2f_conf.parent.mkdir(parents=True, exist_ok=True)
    world.paths.pam_u2f_conf.write_text("# site defaults\nnouserok\n")
    with pytest.raises(SetupError, match=r"pam_u2f\.conf\) has nouserok"):
        registered(world).test_login(NODE)
    assert world.pam.calls == []


def test_with_no_pam_the_test_uses_the_documented_line(world: World) -> None:
    edit_profile(world, "cue userverification=1", "cue nouserok userverification=1")
    setup = world.setup(no_pam=True)
    setup.registered = True
    setup.new_entry = MAPPING
    assert setup.test_login(NODE) is True  # the profile is not enabled, so not used
    assert "nouserok" not in world.pam.calls[0][2]


# Security review: who step 8 says the key is for (M1)


def test_step_8_says_su_polkit_and_ssh_keep_the_password(world: World) -> None:
    world.answer("no")
    after_the_login_test(world).enable_pam(tested=True)
    text = world.console.text
    assert "su, polkit (pkexec, admin dialogs) and SSH" in text
    assert "keep asking for the password, and so does sudo in an SSH session." in text
    assert "polkit." not in text  # the old text listed su and polkit as using the key


def test_the_manual_pam_lines_put_the_local_session_check_before_sudo_s_key(
    world: World,
) -> None:
    world.runner.tools.discard("pam-auth-update")
    world.setup().enable_pam(tested=True)
    text = world.console.text
    assert f"auth [success=ignore default=1] pam_exec.so quiet {LOCAL_SESSION_CHECK}" in text
    assert re.search(r"/etc/pam\.d/su\b", text) is None  # sudo, but not su
