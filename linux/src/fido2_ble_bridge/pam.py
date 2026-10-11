"""Run one PAM authentication against a private config dir (pam_start_confdir, Linux-PAM >= 1.4).

`setup` tests the pam_u2f line this way before enabling it, and the end-to-end tests drive the
real pam_u2f module with it; neither touches /etc/pam.d.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import glob
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

PAM_SUCCESS = 0
PAM_BUF_ERR = 5
PAM_AUTH_ERR = 7
PAM_CONV_ERR = 19
PAM_PROMPT_ECHO_OFF = 1
PAM_PROMPT_ECHO_ON = 2
PAM_ERROR_MSG = 3
PAM_TEXT_INFO = 4

# The relying party pamu2fcfg registers with and pam_u2f checks (-o/-i and origin=). Fixed, so
# renaming the host does not invalidate registrations.
ORIGIN = "pam://fido2-ble-bridge"
# What the PAM profile runs through pam_exec before pam_u2f for sudo, sudo -i and login: it
# exits 0 only for a request from a session at this computer (local_session.py).
LOCAL_SESSION_CHECK = "/opt/fido2-ble-bridge/bin/python -I -m fido2_ble_bridge.local_session"
# What the profile shows (pam_echo) right before pam_u2f asks the key. pam_u2f's own cue only
# comes once the key has answered, and a sleeping key can take the whole connect timeout, so
# without it the login stays silent until the password prompt.
KEY_HINT = (
    "Bluetooth key: press its button, then touch the sensor when it lights up. "
    "No key? Wait for the password prompt."
)

# pam_u2f options (its cfg.c has them all) that setup accepts in a line it enables, besides the
# required authfile= and userverification=1. Anything else is refused: alwaysok and nouserok let
# logins through without the key, openasuser and expand let the user's own files decide, and
# setup does not vouch for options it does not know.
_HARMLESS_FLAGS = frozenset({"cue", "interactive", "nodetect", "debug"})
_HARMLESS_SETTINGS = frozenset(
    {
        "origin",
        "appid",
        "cue_prompt",
        "prompt",
        "max_devices",
        "pinverification",
        "authpending_file",
        "debug_file",
    }
)
_CHECKED_SETTINGS = frozenset({"authfile", "userverification", "userpresence"})

_MODULE_PATTERNS = (
    "lib/*/security/pam_u2f.so",
    "usr/lib/*/security/pam_u2f.so",
    "usr/lib/security/pam_u2f.so",
    "usr/lib64/security/pam_u2f.so",
)


def u2f_arguments(authfile: Path) -> str:
    """pam_u2f's arguments in the shipped PAM profile: fingerprint required, fixed origin."""
    return f"authfile={authfile} origin={ORIGIN} cue userverification=1"


def u2f_option_problems(arguments: Sequence[str], authfile: Path) -> list[str]:
    """What makes pam_u2f with these arguments weaker than the shipped profile, or something
    setup cannot vouch for; empty if nothing. Later arguments override earlier ones, as in
    pam_u2f, so defaults from its config file can be passed in first."""
    problems: list[str] = []
    settings: dict[str, str] = {}
    for argument in arguments:
        name, has_value, value = argument.partition("=")
        if has_value:
            settings[name] = value
            known = name in _HARMLESS_SETTINGS or name in _CHECKED_SETTINGS
        else:
            known = argument in _HARMLESS_FLAGS
        if not known:
            problems.append(argument)
    if settings.get("userverification") != "1":
        problems.append("no userverification=1")
    if settings.get("userpresence", "1") != "1":
        problems.append(f"userpresence={settings['userpresence']}")
    if settings.get("authfile") != str(authfile):
        problems.append(f"authfile is not {authfile}")
    return problems


def config_file_arguments(text: str) -> list[str]:
    """The settings in pam_u2f's own config file (/etc/security/pam_u2f.conf, read by pam_u2f
    1.4 and newer), as module arguments: `name = value` lines, `#` starting a comment."""
    arguments = []
    for line in text.splitlines():
        setting = line.split("#", 1)[0].strip()
        name, has_value, value = setting.partition("=")
        if setting:
            arguments.append(f"{name.strip()}={value.strip()}" if has_value else setting)
    return arguments


def profile_u2f_lines(profile: str) -> list[tuple[str, ...]]:
    """The pam_u2f lines of a pam-auth-update profile's Auth and Auth-Initial blocks, each as
    (module, *arguments)."""
    found = []
    block: str | None = None
    for line in profile.splitlines():
        if not line[:1].isspace():
            block = line[:-1] if line.endswith(":") else None
            continue
        if block not in ("Auth", "Auth-Initial"):
            continue
        text = line.strip()
        words = text.partition("]")[2].split() if text.startswith("[") else text.split()[1:]
        if words and Path(words[0]).name == "pam_u2f.so":
            found.append(tuple(words))
    return found


def find_pam_u2f(root: Path = Path("/")) -> Path | None:
    """pam_u2f.so in the usual module directories (Debian multiarch, Fedora, Arch)."""
    for pattern in _MODULE_PATTERNS:
        if found := sorted(glob.glob(str(root / pattern))):
            return Path(found[0])
    return None


class PamError(Exception):
    """PAM could not start: no libpam, no pam_start_confdir, or no usable stack."""


@dataclass(frozen=True)
class PamResult:
    code: int
    description: str
    messages: list[str]

    @property
    def ok(self) -> bool:
        return self.code == PAM_SUCCESS


class _Message(ctypes.Structure):
    _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]


class _Response(ctypes.Structure):
    _fields_ = [("resp", ctypes.c_void_p), ("resp_retcode", ctypes.c_int)]


_CONV = ctypes.CFUNCTYPE(
    ctypes.c_int,
    ctypes.c_int,
    ctypes.POINTER(ctypes.POINTER(_Message)),
    ctypes.POINTER(ctypes.POINTER(_Response)),
    ctypes.c_void_p,
)


class _Conv(ctypes.Structure):
    _fields_ = [("conv", _CONV), ("appdata_ptr", ctypes.c_void_p)]


def _libpam() -> ctypes.CDLL | None:
    name = ctypes.util.find_library("pam")
    if name is None:
        return None
    try:
        return ctypes.CDLL(name)
    except OSError:
        return None


def available() -> bool:
    libpam = _libpam()
    return libpam is not None and hasattr(libpam, "pam_start_confdir")


def authenticate(
    confdir: Path,
    service: str,
    user: str,
    on_message: Callable[[str], None] | None = None,
) -> PamResult:
    """Run pam_authenticate once for `user` with the stack in confdir/service.

    Prompts are answered with an empty string. Informational and error messages (pam_u2f's
    "Please touch the device.") go to on_message as they arrive, and all messages are returned.
    An exception in on_message, Ctrl-C included, fails the conversation, so the module gives
    up; it is raised again once PAM is done.
    """
    libpam = _libpam()
    if libpam is None or not hasattr(libpam, "pam_start_confdir"):
        raise PamError("this system's PAM has no pam_start_confdir (needs Linux-PAM 1.4 or newer)")
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    libc.calloc.restype = ctypes.c_void_p
    libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    libc.strdup.restype = ctypes.c_void_p
    libc.strdup.argtypes = [ctypes.c_char_p]
    messages: list[str] = []
    raised: list[BaseException] = []

    def converse(
        count: int,
        msgs: ctypes._Pointer[ctypes._Pointer[_Message]],
        resp: ctypes._Pointer[ctypes._Pointer[_Response]],
        _appdata: int | None,
    ) -> int:
        # Nothing may escape into C, not even KeyboardInterrupt: ctypes would only print it and
        # hand PAM a default return value, which reads as success. It is kept and raised again
        # once PAM is done, and every later conversation fails at once.
        if raised:
            return PAM_CONV_ERR
        try:
            styles = []
            for i in range(count):
                message = msgs[i].contents
                text = (message.msg or b"").decode(errors="replace")
                messages.append(text)
                if on_message is not None and message.msg_style in (PAM_TEXT_INFO, PAM_ERROR_MSG):
                    on_message(text)
                styles.append(message.msg_style)
            # PAM frees the response array and strings, so both come from the C allocator.
            array = libc.calloc(count, ctypes.sizeof(_Response))
            if not array:
                return PAM_BUF_ERR
            responses = ctypes.cast(array, ctypes.POINTER(_Response))
            for i, style in enumerate(styles):
                if style in (PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON):
                    responses[i].resp = libc.strdup(b"")
            resp[0] = responses
        except BaseException as exc:
            raised.append(exc)
            return PAM_CONV_ERR
        return PAM_SUCCESS

    callback = _CONV(converse)
    conversation = _Conv(callback, None)
    handle = ctypes.c_void_p()
    libpam.pam_start_confdir.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.POINTER(_Conv),
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    libpam.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
    libpam.pam_strerror.argtypes = [ctypes.c_void_p, ctypes.c_int]
    libpam.pam_strerror.restype = ctypes.c_char_p
    libpam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
    started = libpam.pam_start_confdir(
        service.encode(),
        user.encode(),
        ctypes.byref(conversation),
        str(confdir).encode(),
        ctypes.byref(handle),
    )
    if started != PAM_SUCCESS:
        raise PamError(f"pam_start_confdir failed with PAM status {started}")
    result = PAM_CONV_ERR
    try:
        result = int(libpam.pam_authenticate(handle, 0))
        description = (libpam.pam_strerror(handle, result) or b"").decode(errors="replace")
    finally:
        libpam.pam_end(handle, result)
    if raised:
        raise raised[0]
    return PamResult(result, description, messages)
