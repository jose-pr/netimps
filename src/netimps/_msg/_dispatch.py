"""``recvmsg``, ``sendmsg`` and the CMSG sizes: native where CPython has them, Winsock on Windows."""

from __future__ import annotations

import errno as _errno
import socket as _socket
import sys as _sys
from typing import (
    Any,
    Callable,
    Iterable,
    List,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
)

__all__ = ["recvmsg", "sendmsg", "CMSG_LEN", "CMSG_SPACE", "has_recvmsg"]


_IS_WINDOWS = _sys.platform == "win32"

_F = TypeVar("_F", bound=Callable[..., Any])

_MARK = "_netimps_installed"


def _mark(function: _F) -> _F:
    """Tag *function* as one this package installs into another module.

    A second copy of the package in the same process (a reloader, a test
    runner) finds the first copy's installed functions on :mod:`socket` and
    :mod:`os`; the tag is how it tells them from the platform's own.
    """
    setattr(function, _MARK, True)
    return function


def _is_ours(candidate: "Any") -> bool:
    return getattr(candidate, _MARK, False) is True


def _native(candidate: "Any") -> "Any":
    """*candidate* when the platform provides it, ``None`` when it is absent or
    was installed by a copy of this package."""
    return None if _is_ours(candidate) else candidate


#: Captured **at import, before any patching**, which is what makes the
#: delegation below safe: once :func:`patch_socket_module` has installed our
#: function as ``socket.socket.recvmsg``, a ``hasattr`` check would find it and
#: :func:`recvmsg` would call itself forever. Binding the native method up
#: front removes the possibility rather than guarding against it. A function
#: another copy of this package installed is not native.
_NATIVE_RECVMSG = _native(getattr(_socket.socket, "recvmsg", None))
_NATIVE_SENDMSG = _native(getattr(_socket.socket, "sendmsg", None))
_NATIVE_CMSG_LEN = _native(getattr(_socket, "CMSG_LEN", None))
_NATIVE_CMSG_SPACE = _native(getattr(_socket, "CMSG_SPACE", None))


def _load_winsock() -> "Any":
    """Import the Winsock bindings, or ``None`` if they are unusable.

    Lazy and guarded: :mod:`netimps._winsock` touches :class:`ctypes.WinDLL`
    and must never be imported off Windows. A failure here is a degraded
    platform, not an error -- the callers below raise a specific
    :class:`OSError` instead, so the reason surfaces at the call rather than at
    ``import netimps``.
    """
    if not _IS_WINDOWS:
        return None
    try:
        from .. import _winsock
    except Exception:  # pragma: no cover - a Windows without ws2_32
        return None
    return _winsock


_winsock_module = _load_winsock()


def _unsupported(name: str) -> "Any":
    raise OSError(
        _errno.ENOTSUP,
        "%s is not available on this platform: CPython provides no %s and the "
        "Winsock fallback did not load" % (name, name),
    )


def has_recvmsg() -> bool:
    """Whether :func:`recvmsg` and :func:`sendmsg` can actually run here.

    ``True`` on POSIX, and on Windows when the Winsock bindings loaded. Prefer
    this to probing :mod:`socket` for a method name, which answers a different
    question once the patch is installed.
    """
    return _NATIVE_RECVMSG is not None or _winsock_module is not None


@_mark
def CMSG_LEN(length: int) -> int:
    """Bytes one cmsg of ``length`` payload occupies, header included.

    Native where CPython provides it; computed from ``WSACMSGHDR`` and pointer
    alignment on Windows.
    """
    if _NATIVE_CMSG_LEN is not None:
        return _NATIVE_CMSG_LEN(length)
    if _winsock_module is not None:
        return _winsock_module.CMSG_LEN(length)
    return _unsupported("CMSG_LEN")


@_mark
def CMSG_SPACE(length: int) -> int:
    """Buffer space one cmsg of ``length`` payload needs, padding included.

    This is the one to size an ``ancbufsize`` with: the difference from
    :func:`CMSG_LEN` is the trailing pad that lets a following header start
    aligned, and leaving it out is how a second cmsg gets quietly truncated.
    """
    if _NATIVE_CMSG_SPACE is not None:
        return _NATIVE_CMSG_SPACE(length)
    if _winsock_module is not None:
        return _winsock_module.CMSG_SPACE(length)
    return _unsupported("CMSG_SPACE")


def recvmsg(
    sock: "Any",
    bufsize: int,
    ancbufsize: int = 0,
    flags: int = 0,
) -> "Tuple[bytes, List[Tuple[int, int, bytes]], int, Optional[Any]]":
    """Receive a datagram with its ancillary data, on any platform.

    Same signature and same 4-tuple as :meth:`socket.socket.recvmsg`:
    ``(data, ancdata, msg_flags, address)``, where ``ancdata`` is a list of
    ``(cmsg_level, cmsg_type, cmsg_data)``.

    ``address`` is ``(host, port)`` for ``AF_INET`` and
    ``(host, port, flowinfo, scope_id)`` for ``AF_INET6``.

    :raises OSError: with ``ENOTSUP`` where neither CPython nor Winsock can
        serve it. Receiving errors propagate as the usual ``OSError``
        subclasses -- :class:`BlockingIOError` on an empty non-blocking socket,
        on Windows as well as POSIX.
    """
    if _NATIVE_RECVMSG is not None:
        return _NATIVE_RECVMSG(sock, bufsize, ancbufsize, flags)
    if _winsock_module is not None:
        return _winsock_module.recvmsg(sock, bufsize, ancbufsize, flags)
    return _unsupported("recvmsg")


def sendmsg(
    sock: "Any",
    buffers: "Sequence[bytes]",
    ancdata: "Iterable[Tuple[int, int, bytes]]" = (),
    flags: int = 0,
    address: "Optional[Any]" = None,
) -> int:
    """Send a datagram with ancillary data, on any platform.

    Same signature as :meth:`socket.socket.sendmsg`: ``buffers`` is a sequence
    of bytes-like objects (not a bare ``bytes``), ``ancdata`` a sequence of
    ``(cmsg_level, cmsg_type, cmsg_data)``, and the return is the byte count
    sent.

    A v6 ``address`` accepts a 2-, 3- or 4-tuple, and a ``%zone`` suffix on the
    host is honoured when ``scope_id`` is absent.

    :raises OSError: with ``ENOTSUP`` where neither CPython nor Winsock can
        serve it.
    """
    if _NATIVE_SENDMSG is not None:
        return _NATIVE_SENDMSG(sock, buffers, ancdata, flags, address)
    if _winsock_module is not None:
        return _winsock_module.sendmsg(sock, buffers, ancdata, flags, address)
    return _unsupported("sendmsg")
