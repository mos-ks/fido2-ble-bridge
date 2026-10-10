"""Run one PAM authentication against a private config dir (pam_start_confdir, Linux-PAM >= 1.4).

Lets the end-to-end test drive the real pam_u2f module without touching /etc/pam.d.
"""

from __future__ import annotations

import ctypes
import ctypes.util
from pathlib import Path

PAM_SUCCESS = 0
PAM_AUTH_ERR = 7
PAM_PROMPT_ECHO_OFF = 1
PAM_PROMPT_ECHO_ON = 2


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


def available() -> bool:
    name = ctypes.util.find_library("pam")
    return name is not None and hasattr(ctypes.CDLL(name), "pam_start_confdir")


def authenticate(confdir: Path, service: str, user: str) -> tuple[int, list[str]]:
    libpam = ctypes.CDLL(ctypes.util.find_library("pam"))
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    libc.calloc.restype = ctypes.c_void_p
    libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    libc.strdup.restype = ctypes.c_void_p
    libc.strdup.argtypes = [ctypes.c_char_p]
    messages: list[str] = []

    def converse(
        count: int,
        msgs: ctypes._Pointer[ctypes._Pointer[_Message]],
        resp: ctypes._Pointer[ctypes._Pointer[_Response]],
        _appdata: int | None,
    ) -> int:
        # PAM frees the response array and strings, so both come from the C allocator.
        array = ctypes.cast(libc.calloc(count, ctypes.sizeof(_Response)), ctypes.POINTER(_Response))
        for i in range(count):
            message = msgs[i].contents
            messages.append((message.msg or b"").decode())
            if message.msg_style in (PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON):
                array[i].resp = libc.strdup(b"")
        resp[0] = array
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
    libpam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
    started = libpam.pam_start_confdir(
        service.encode(),
        user.encode(),
        ctypes.byref(conversation),
        str(confdir).encode(),
        ctypes.byref(handle),
    )
    if started != PAM_SUCCESS:
        raise RuntimeError(f"pam_start_confdir failed: {started}")
    result = int(libpam.pam_authenticate(handle, 0))
    libpam.pam_end(handle, result)
    return result, messages
