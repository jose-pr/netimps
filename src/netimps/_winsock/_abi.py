"""The Winsock binding: ``ws2_32``, its structures, and the argument types of what is called."""

from __future__ import annotations

import ctypes as _ctypes
from typing import Any

# Windows-only names; mypy checks this module on every platform even though it
# is only ever imported on win32, so each one carries the guard explicitly.
_ws2 = _ctypes.WinDLL("ws2_32")  # type: ignore[attr-defined]

#: ``UINT_PTR``. A Windows SOCKET is a handle, not a small int as on POSIX, so
#: it must be pointer-width or the high bits are truncated on 64-bit.
_SOCKET = _ctypes.c_size_t

_DWORD = _ctypes.c_uint32
_ULONG = _ctypes.c_uint32

_SIO_GET_EXTENSION_FUNCTION_POINTER = 0xC8000006

#: Alignment for cmsg data and for the step between headers. Measured, and it
#: is pointer width rather than the 4 a reader might assume from Linux.
_ALIGN = _ctypes.sizeof(_ctypes.c_void_p)

_WSAEMSGSIZE = 10040
_WSAEWOULDBLOCK = 10035


class _GUID(_ctypes.Structure):
    _fields_ = [
        ("Data1", _DWORD),
        ("Data2", _ctypes.c_uint16),
        ("Data3", _ctypes.c_uint16),
        ("Data4", _ctypes.c_ubyte * 8),
    ]


#: ``{F689D7C8-6F1F-436B-8A53-E54FE351C322}``
_WSAID_WSARECVMSG = _GUID(
    0xF689D7C8,
    0x6F1F,
    0x436B,
    (_ctypes.c_ubyte * 8)(0x8A, 0x53, 0xE5, 0x4F, 0xE3, 0x51, 0xC3, 0x22),
)


class _WSABUF(_ctypes.Structure):
    _fields_ = [("len", _ULONG), ("buf", _ctypes.c_void_p)]


class _WSAMSG(_ctypes.Structure):
    _fields_ = [
        ("name", _ctypes.c_void_p),
        ("namelen", _ctypes.c_int),
        ("lpBuffers", _ctypes.POINTER(_WSABUF)),
        ("dwBufferCount", _ULONG),
        ("Control", _WSABUF),
        ("dwFlags", _ULONG),
    ]


class _WSACMSGHDR(_ctypes.Structure):
    _fields_ = [
        ("cmsg_len", _ctypes.c_size_t),
        ("cmsg_level", _ctypes.c_int),
        ("cmsg_type", _ctypes.c_int),
    ]


_CMSGHDR_SIZE = _ctypes.sizeof(_WSACMSGHDR)


class _SOCKADDR_IN(_ctypes.Structure):
    _fields_ = [
        ("sin_family", _ctypes.c_ushort),
        ("sin_port", _ctypes.c_ushort),
        ("sin_addr", _ctypes.c_ubyte * 4),
        ("sin_zero", _ctypes.c_char * 8),
    ]


class _SOCKADDR_IN6(_ctypes.Structure):
    _fields_ = [
        ("sin6_family", _ctypes.c_ushort),
        ("sin6_port", _ctypes.c_ushort),
        ("sin6_flowinfo", _ULONG),
        ("sin6_addr", _ctypes.c_ubyte * 16),
        ("sin6_scope_id", _ULONG),
    ]


#: Big enough for either family plus slack, so one buffer serves both.
_SOCKADDR_STORAGE_SIZE = 128

_LPFN_WSARECVMSG = _ctypes.WINFUNCTYPE(  # type: ignore[attr-defined]
    _ctypes.c_int,
    _SOCKET,
    _ctypes.POINTER(_WSAMSG),
    _ctypes.POINTER(_DWORD),
    _ctypes.c_void_p,
    _ctypes.c_void_p,
)

_ws2.WSAIoctl.argtypes = [
    _SOCKET,
    _DWORD,
    _ctypes.c_void_p,
    _DWORD,
    _ctypes.c_void_p,
    _DWORD,
    _ctypes.POINTER(_DWORD),
    _ctypes.c_void_p,
    _ctypes.c_void_p,
]
_ws2.WSAIoctl.restype = _ctypes.c_int

#: ``WSASend`` is the scatter-gather send that works on a **stream** socket.
#: ``WSASendMsg`` does not: measured on Windows 11 build 28000, it answers
#: ``WSAEINVAL`` for a connected ``SOCK_STREAM`` while accepting a connected
#: ``SOCK_DGRAM``, so the refusal is about the socket *type* and not about
#: being connected. ``WSASend`` takes no destination and no control buffer,
#: which is exactly the buffers-only case -- see :func:`sendmsg` for the
#: dispatch.
_ws2.WSASend.argtypes = [
    _SOCKET,
    _ctypes.POINTER(_WSABUF),
    _ULONG,
    _ctypes.POINTER(_DWORD),
    _DWORD,
    _ctypes.c_void_p,
    _ctypes.c_void_p,
]
_ws2.WSASend.restype = _ctypes.c_int

#: ``WSARecv``, the receive that works on a **stream** socket; ``WSARecvMsg``
#: answers ``WSAEINVAL`` for one, as ``WSASendMsg`` does.
_ws2.WSARecv.argtypes = [
    _SOCKET,
    _ctypes.POINTER(_WSABUF),
    _ULONG,
    _ctypes.POINTER(_DWORD),
    _ctypes.POINTER(_DWORD),
    _ctypes.c_void_p,
    _ctypes.c_void_p,
]
_ws2.WSARecv.restype = _ctypes.c_int

_ws2.WSASendMsg.argtypes = [
    _SOCKET,
    _ctypes.POINTER(_WSAMSG),
    _DWORD,
    _ctypes.POINTER(_DWORD),
    _ctypes.c_void_p,
    _ctypes.c_void_p,
]
_ws2.WSASendMsg.restype = _ctypes.c_int

_ws2.WSAGetLastError.argtypes = []
_ws2.WSAGetLastError.restype = _ctypes.c_int


def available() -> bool:
    """Whether this module's bindings loaded.

    Always ``True`` once the module imports -- the import itself is what fails
    on a platform without ``ws2_32``.
    """
    return True


def _raise_last_error() -> "Any":
    """Turn ``WSAGetLastError`` into the ``OSError`` subclass CPython would.

    ``ctypes.WinError`` resolves the Winsock code through ``errno``, so
    ``WSAEWOULDBLOCK`` arrives as :class:`BlockingIOError` and a refusal as
    :class:`ConnectionResetError` -- which is what makes this a drop-in for the
    POSIX method rather than a parallel error vocabulary.
    """
    raise _ctypes.WinError(_ws2.WSAGetLastError())  # type: ignore[attr-defined]
