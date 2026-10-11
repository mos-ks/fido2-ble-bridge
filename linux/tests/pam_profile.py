"""The auth stack pam-auth-update builds from the shipped PAM profile, for tests that run it
through the real libpam (pam_start_confdir), outside /etc/pam.d."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from fido2_ble_bridge import pam

PROFILE = Path(__file__).resolve().parents[1] / "packaging" / "pam-configs" / "fido2-ble-bridge"
U2F_LINE = f"pam_u2f.so {pam.u2f_arguments(Path('/etc/fido2-ble-bridge/u2f_mappings'))}"
CHECK = pam.LOCAL_SESSION_CHECK
HINT = next(
    line.split("pam_echo.so ", 1)[1]
    for line in PROFILE.read_text().splitlines()
    if "pam_echo.so " in line
)
"""What the profile shows before it asks the key."""


def stack_from_profile(replace: Mapping[str, str], fallback_module: str = "pam_deny.so") -> str:
    """The profile's Auth lines as pam-auth-update writes them into common-auth on Ubuntu
    24.04: `end` turned into a jump past the Primary block, then the password module (pam_unix;
    by default pam_deny here, a password that never matches), then the stock tail. Each key of
    `replace` found in a line's module part is replaced by its value."""
    text = PROFILE.read_text()
    block = text.split("\nAuth:\n", 1)[1].split("\nAuth-Initial:", 1)[0]
    primary = [line.strip() for line in block.splitlines() if line.strip()]
    primary.append(f"[success=end default=ignore]\t{fallback_module}")
    lines = []
    for index, line in enumerate(primary):
        control, rest = line.split("]", 1)
        control = control.replace("end", str(len(primary) - index)) + "]"
        for old, new in replace.items():
            rest = rest.replace(old, new)
        lines.append(f"auth {control} {rest.strip()}")
    lines += ["auth requisite pam_deny.so", "auth required pam_permit.so"]
    return "\n".join(lines) + "\n"
