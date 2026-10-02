"""Cross-platform ``recvmsg`` / ``sendmsg``, and the optional stdlib patch.

Two layers, and the first does not depend on the second:

1. **Functions that always work** -- :func:`recvmsg`, :func:`sendmsg`,
   :func:`CMSG_LEN`, :func:`CMSG_SPACE`. Call them on any platform. On POSIX
   they delegate to CPython's own methods; on Windows they go through
   :mod:`netimps._winsock` and ``WSARecvMsg``/``WSASendMsg``. This is the
   supported surface, and it is complete without anything being patched.
2. **An optional patch** -- :func:`patch_socket_module` installs the same
   behaviour onto :class:`socket.socket` and the :mod:`socket` module, so that
   ordinary ``sock.recvmsg(...)`` code written for POSIX runs unchanged on
   Windows. netimps installs it on import; see the opt-out below.

Both families are supported throughout. ``AF_INET6`` senders come back as the
4-tuple ``(host, port, flowinfo, scope_id)`` that ``recvfrom`` returns, and a
v6 destination may be given as a 2-, 3- or 4-tuple with an optional ``%zone``
suffix -- the same latitude ``sendto`` allows.

**Why the patch also installs ``CMSG_LEN``/``CMSG_SPACE``.** Windows has
neither. The standard POSIX idiom is to feature-detect, then size a control
buffer, then receive::

    if hasattr(sock, "recvmsg"):
        data, anc, flags, addr = sock.recvmsg(1500, socket.CMSG_SPACE(64))

Patching only ``recvmsg`` would let that detection succeed and then fail on the
*next* line, turning "this platform cannot do it" into "this library is
broken". The patch is all four names or none.

**What the patch deliberately does not do: fake Linux's byte layouts.** The
cmsg payloads stay exactly as the platform produces them, because they genuinely
differ -- Windows' ``IN_PKTINFO`` is ``{addr; ifindex}`` at 8 bytes, Linux's is
``{ifindex; spec_dst; addr}`` at 12, and ``IP_PKTINFO`` is 19 here against 8
there. Normalising the bytes would let POSIX-shaped parsing code read a
*plausible wrong address* instead of failing honestly, which is the worse
outcome. Socket constants are not portable on any other platform pair either.
:mod:`netimps._udp` owns the per-platform layout table; consult it rather than
assuming.

**Opting out.** Set ``NETIMPS_NO_SOCKET_PATCH=1`` in the environment before the
first ``import netimps``, or call ``patch_socket_module(False)`` afterwards to
undo it. The environment variable exists because the decision has to be
expressible *before* import, which a function call cannot be. The patch only
ever **adds** names it finds missing: it never replaces a method the platform
already provides, so if CPython ever ships ``recvmsg`` on Windows this stands
down by itself.
"""

import errno as _errno
import os as _os
import socket as _socket
import sys as _sys
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "recvmsg",
    "sendmsg",
    "CMSG_LEN",
    "CMSG_SPACE",
    "patch_socket_module",
    "socket_patched",
    "supports_recvmsg",
]

_IS_WINDOWS = _sys.platform == "win32"

#: Captured **at import, before any patching**, which is what makes the
#: delegation below safe: once :func:`patch_socket_module` has installed our
#: function as ``socket.socket.recvmsg``, a ``hasattr`` check would find it and
#: :func:`recvmsg` would call itself forever. Binding the native method up
#: front removes the possibility rather than guarding against it.
_NATIVE_RECVMSG = getattr(_socket.socket, "recvmsg", None)
_NATIVE_SENDMSG = getattr(_socket.socket, "sendmsg", None)
_NATIVE_CMSG_LEN = getattr(_socket, "CMSG_LEN", None)
_NATIVE_CMSG_SPACE = getattr(_socket, "CMSG_SPACE", None)


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
        from . import _winsock
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


def supports_recvmsg() -> bool:
    """Whether :func:`recvmsg` and :func:`sendmsg` can actually run here.

    ``True`` on POSIX, and on Windows when the Winsock bindings loaded. Prefer
    this to probing :mod:`socket` for a method name, which answers a different
    question once the patch is installed.
    """
    return _NATIVE_RECVMSG is not None or _winsock_module is not None


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


#: What :func:`patch_socket_module` installed, so it can be undone exactly.
#: Empty means nothing is installed, which is the state on every platform whose
#: CPython already provides these.
_installed: "Dict[str, Any]" = {}


def socket_patched() -> bool:
    """Whether netimps has added anything to :mod:`socket` right now.

    A function rather than a constant because the answer changes when
    :func:`patch_socket_module` is called, and a module-level flag copied by
    ``from netimps import ...`` would go stale at the first toggle.
    """
    return bool(_installed)


def patch_socket_module(enable: bool = True) -> "List[str]":
    """Add ``recvmsg``/``sendmsg``/``CMSG_LEN``/``CMSG_SPACE`` where missing.

    netimps calls this on import, so ``sock.recvmsg(...)`` works on Windows
    without the caller changing anything. Returns the names it changed, newest
    call only -- an empty list means there was nothing to do.

    Idempotent in both directions, and strictly additive: a name the platform
    already provides is never replaced, so on Linux and macOS this is a
    verified no-op. ``enable=False`` removes exactly what was installed,
    leaving a natively-provided name alone.

    :param enable: install when true, restore the original state when false.
    :returns: the names added or removed by this call.
    """
    changed: "List[str]" = []

    if not enable:
        for name in list(_installed):
            target, attribute = _installed.pop(name)
            try:
                delattr(target, attribute)
            except AttributeError:  # pragma: no cover - already gone
                pass
            changed.append(name)
        return changed

    if not supports_recvmsg():
        # Nothing to offer: leave `socket` exactly as it was rather than
        # installing a function whose only behaviour is to raise.
        return changed

    for name, value in (
        ("socket.recvmsg", _patched_recvmsg),
        ("socket.sendmsg", _patched_sendmsg),
    ):
        attribute = name.split(".", 1)[1]
        if name in _installed or hasattr(_socket.socket, attribute):
            continue
        setattr(_socket.socket, attribute, value)
        _installed[name] = (_socket.socket, attribute)
        changed.append(name)

    # A separate loop with its own names rather than reusing `name, value`: the
    # two tables hold different callable shapes, and mypy types a reused loop
    # variable from whichever came first.
    for helper, function in (
        ("CMSG_LEN", CMSG_LEN),
        ("CMSG_SPACE", CMSG_SPACE),
    ):
        if helper in _installed or hasattr(_socket, helper):
            continue
        setattr(_socket, helper, function)
        _installed[helper] = (_socket, helper)
        changed.append(helper)

    return changed


def _patched_recvmsg(
    self: "Any",
    bufsize: int,
    ancbufsize: int = 0,
    flags: int = 0,
) -> "Tuple[bytes, List[Tuple[int, int, bytes]], int, Optional[Any]]":
    """Bound-method form of :func:`recvmsg`, installed on :class:`socket.socket`."""
    return recvmsg(self, bufsize, ancbufsize, flags)


def _patched_sendmsg(
    self: "Any",
    buffers: "Sequence[bytes]",
    ancdata: "Iterable[Tuple[int, int, bytes]]" = (),
    flags: int = 0,
    address: "Optional[Any]" = None,
) -> int:
    """Bound-method form of :func:`sendmsg`, installed on :class:`socket.socket`."""
    return sendmsg(self, buffers, ancdata, flags, address)


def _patch_requested() -> bool:
    """Whether the import-time patch is wanted.

    Read once, at import. ``NETIMPS_NO_SOCKET_PATCH`` set to anything other
    than an explicit falsey spelling disables it, so ``=1``, ``=true`` and
    ``=yes`` all work and ``=0`` does not accidentally disable it.
    """
    value = _os.environ.get("NETIMPS_NO_SOCKET_PATCH")
    if value is None:
        return True
    return value.strip().lower() in ("", "0", "false", "no", "off")
