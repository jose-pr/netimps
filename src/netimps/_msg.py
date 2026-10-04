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

**Opting out.** Set ``NETIMPS_SOCKET_PATCH=0`` in the environment before the
first ``import netimps``, or call ``patch_socket_module(False)`` afterwards to
undo it. The environment variable exists because the decision has to be
expressible *before* import, which a function call cannot be. The patch only
ever **adds** names it finds missing: it never replaces a method the platform
already provides, so if CPython ever ships ``recvmsg`` on Windows this stands
down by itself.
"""

from __future__ import annotations

import errno as _errno
import os as _os
import socket as _socket
import struct as _struct
import sys as _sys
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "recvmsg",
    "sendmsg",
    "CMSG_LEN",
    "CMSG_SPACE",
    "patch_socket_module",
    "is_socket_patched",
    "has_recvmsg",
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


def has_recvmsg() -> bool:
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


#: Windows ``IN_PKTINFO`` is ``{IN_ADDR ipi_addr; ULONG ipi_ifindex}`` -- 8 bytes,
#: **address first**. POSIX ``in_pktinfo`` is
#: ``{unsigned ipi_ifindex; in_addr ipi_spec_dst; in_addr ipi_addr}`` -- 12 bytes,
#: **index first**. Not a length difference: the field order is reversed.
_WIN_PKTINFO_V4 = "=4sI"
_POSIX_PKTINFO_V4 = "=I4s4s"

#: ``IP_PKTINFO`` as this platform spells it. 19 on Windows, 8 on Linux, 26 on
#: macOS -- so a caller comparing against ``socket.IP_PKTINFO`` matches the
#: local number, which is why the *type* is left alone while the payload is
#: reshaped.
_LOCAL_IP_PKTINFO = getattr(_socket, "IP_PKTINFO", 19 if _IS_WINDOWS else None)

#: Whether the patched methods must reshape anything. Only Windows differs; the
#: v6 ``in6_pktinfo`` layout (``{addr; ifindex}``, 20 bytes) is identical on all
#: three, so v6 is never touched.
_NEEDS_POSIX_SHAPE = _IS_WINDOWS


def _to_posix_shape(
    ancdata: "List[Tuple[int, int, bytes]]",
) -> "List[Tuple[int, int, bytes]]":
    """Re-lay a Windows ``IP_PKTINFO`` payload into the POSIX field order.

    Used **only** by the patched :meth:`socket.socket.recvmsg`, never by
    :func:`recvmsg`. That split is the point: a caller who asked for
    ``netimps.recvmsg`` gets the platform's own bytes, while a caller reaching
    ``sock.recvmsg`` is reaching for a method that exists on POSIX and should
    therefore get what POSIX would have put there. Installing the name without
    the layout is a half-impersonation, and the half that is missing is the one
    that makes POSIX-shaped parsing code wrong.

    ``ipi_spec_dst`` is filled with **zero**, because Windows does not report
    it and inventing it would be worse than leaving it empty:

    - Zero is also what **macOS** puts there -- measured on a CI runner,
      ``01000000 00000000 7f000001`` for a unicast to ``127.0.0.1``. So this
      makes Windows behave like the platform that already answers this way,
      rather than like a fourth thing.
    - Copying ``ipi_addr`` into it would be a *plausible wrong address* in the
      case that matters most. Measured on Linux: for a broadcast the two fields
      genuinely differ -- ``ipi_spec_dst`` is the local interface address
      (``172.18.120.118``) while ``ipi_addr`` is ``255.255.255.255``. Code that
      reads ``spec_dst`` reads it precisely to get the local address, so handing
      it the broadcast address would silently corrupt exactly the field it
      wanted. Zero is visibly wrong; ``255.255.255.255`` is not.

    So a caller reading ``ipi_addr`` (field 3) gets the right answer, and one
    reading ``ipi_spec_dst`` (field 2) gets ``0.0.0.0`` -- the same answer it
    already gets on macOS today. Neither silently misreads a different address,
    and neither raises ``struct.error`` on an 8-byte buffer any more.
    """
    if not _NEEDS_POSIX_SHAPE or _LOCAL_IP_PKTINFO is None:
        return ancdata
    out: "List[Tuple[int, int, bytes]]" = []
    for level, ctype, cdata in ancdata:
        if (
            level == _socket.IPPROTO_IP
            and ctype == _LOCAL_IP_PKTINFO
            and len(cdata) == _struct.calcsize(_WIN_PKTINFO_V4)
        ):
            address, index = _struct.unpack(_WIN_PKTINFO_V4, cdata)
            cdata = _struct.pack(_POSIX_PKTINFO_V4, index, b"\x00" * 4, address)
        out.append((level, ctype, cdata))
    return out


def _from_posix_shape(
    ancdata: "Iterable[Tuple[int, int, bytes]]",
) -> "List[Tuple[int, int, bytes]]":
    """Accept either layout on send, chosen by length.

    The mirror of :func:`_to_posix_shape`, so POSIX-shaped code that builds a
    12-byte ``in_pktinfo`` to pin a source is understood as well as code that
    builds the native 8-byte one. Unambiguous, because the two sizes differ and
    neither is a valid length for the other.

    ``ipi_spec_dst`` is the field POSIX uses to select the source address, so it
    wins when set; ``ipi_addr`` is the fallback. That is the opposite of the
    receive direction, and it is what POSIX itself does -- on receive
    ``ipi_addr`` is the destination that arrived, on send it is ignored.
    """
    items = [(int(level), int(ctype), bytes(data)) for level, ctype, data in ancdata]
    if not _NEEDS_POSIX_SHAPE or _LOCAL_IP_PKTINFO is None:
        return items
    out: "List[Tuple[int, int, bytes]]" = []
    posix_size = _struct.calcsize(_POSIX_PKTINFO_V4)
    for level, ctype, cdata in items:
        if (
            level == _socket.IPPROTO_IP
            and ctype == _LOCAL_IP_PKTINFO
            and len(cdata) == posix_size
        ):
            index, spec_dst, address = _struct.unpack(_POSIX_PKTINFO_V4, cdata)
            source = spec_dst if spec_dst != b"\x00" * 4 else address
            cdata = _struct.pack(_WIN_PKTINFO_V4, source, index)
        out.append((level, ctype, cdata))
    return out


#: What :func:`patch_socket_module` installed, so it can be undone exactly.
#: Empty means nothing is installed, which is the state on every platform whose
#: CPython already provides these.
#: What ``SC_IOV_MAX`` is reported as where the platform has no ``sysconf``.
#:
#: **There is nothing to query.** Windows exposes no buffer-count limit: the
#: socket module has no ``IOV``-like name, ``WSASend``'s ``dwBufferCount`` is a
#: bare ``DWORD``, and measured on build 28000 it accepted **1048576** buffers
#: in one call -- the bound is memory, not a kernel ceiling. The only genuinely
#: system-reported limit nearby is ``SO_MAX_MSG_SIZE`` (65507 for UDP, -1 for
#: TCP), which caps *bytes per datagram* rather than buffers per call and so
#: answers a different question.
#:
#: 1024 therefore matches Linux's real ``IOV_MAX``: a caller batching by this
#: number behaves identically on both platforms, and since Windows has no limit
#: nobody is worse off here than they already are on POSIX. It is a batch size,
#: not a ceiling, and that is the whole reason it can be a constant.
_IOV_MAX = 1024

#: The only name the shim answers. Everything else raises, because inventing
#: numbers for ``SC_OPEN_MAX`` or ``SC_NPROCESSORS_ONLN`` would be guessing at
#: Windows limits that have different real answers and different right ways to
#: ask for them.
_SYSCONF_VALUES = {"SC_IOV_MAX": _IOV_MAX}


def _shim_sysconf(name: "Any") -> int:
    """Stand in for ``os.sysconf`` where the platform has none.

    Needed only because patching ``socket.socket.sendmsg`` breaks an invariant
    the stdlib relies on: ``sendmsg`` and ``os.sysconf`` are both POSIX and have
    always travelled together, so ``hasattr(socket.socket, "sendmsg")`` has been
    a sound proxy for "``os.sysconf`` is available too". CPython's
    ``asyncio/selector_events`` reads exactly that way at import time::

        _HAS_SENDMSG = hasattr(socket.socket, 'sendmsg')
        if _HAS_SENDMSG:
            try: SC_IOV_MAX = os.sysconf('SC_IOV_MAX')
            except OSError: _HAS_SENDMSG = False

    With ``sendmsg`` present and ``os.sysconf`` absent, that is an uncaught
    ``AttributeError`` and ``import asyncio`` dies.

    **Per name, not one blanket answer**, because the three stdlib callers guard
    differently and no single behaviour satisfies them all:

    ====================================  =============================
    caller                                catches
    ====================================  =============================
    ``asyncio/selector_events.py``        ``OSError``
    ``concurrent/futures/process.py``     ``(AttributeError, ValueError)``
    ``multiprocessing/util.py``           ``Exception``
    ====================================  =============================

    Measured: raising ``OSError`` for everything rescues asyncio and breaks
    ``ProcessPoolExecutor``; raising ``ValueError`` or ``AttributeError`` for
    everything does the reverse. So ``SC_IOV_MAX`` returns a value -- which is
    now honest, since :func:`sendmsg` works on a stream socket via ``WSASend`` --
    and every other name raises :class:`ValueError`, which is both what POSIX
    ``sysconf`` does for an unrecognised name and what the other two callers
    already handle.

    (``asyncio``'s guard is the outlier here. ``concurrent.futures`` catches
    ``AttributeError`` with the comment "sysconf not available or setting not
    available", so handling a missing ``sysconf`` is the established convention
    and asyncio simply misses it. Worth reporting upstream; not something to wait
    on.)
    """
    try:
        return _SYSCONF_VALUES[name]
    except (KeyError, TypeError):
        raise ValueError("unrecognized configuration name %r" % (name,))


_installed: "Dict[str, Any]" = {}


def is_socket_patched() -> bool:
    """Whether netimps has added anything to :mod:`socket` right now.

    A function rather than a constant because the answer changes when
    :func:`patch_socket_module` is called, and a module-level flag copied by
    ``from netimps import ...`` would go stale at the first toggle.
    """
    return bool(_installed)


def patch_socket_module(
    enable: bool = True, iov_max: "Optional[int]" = None
) -> "List[str]":
    """Add ``recvmsg``/``sendmsg``/``CMSG_LEN``/``CMSG_SPACE`` where missing.

    netimps calls this on import, so ``sock.recvmsg(...)`` works on Windows
    without the caller changing anything. Returns the names it changed, newest
    call only -- an empty list means there was nothing to do.

    Idempotent in both directions, and strictly additive: a name the platform
    already provides is never replaced, so on Linux and macOS this is a
    verified no-op. ``enable=False`` removes exactly what was installed,
    leaving a natively-provided name alone.

    On a platform with no ``os.sysconf`` this also installs one -- see
    :func:`_shim_sysconf` for why that is part of the same patch rather than a
    separate feature.

    :param enable: install when true, restore the original state when false.
    :param iov_max: what the installed ``os.sysconf`` reports for
        ``SC_IOV_MAX``. Default :data:`_IOV_MAX` (1024, matching Linux).

        **This is a batch size, not a ceiling, and it is a choice rather than a
        measurement** -- which is why it is a parameter. Windows reports no
        buffer-count limit anywhere (no ``IOV``-like socket name;
        ``WSASend``'s ``dwBufferCount`` is a bare ``DWORD``, and 1048576
        buffers in one call were accepted on build 28000), and the system limit
        is not settable on POSIX either: Linux's is
        ``#define UIO_MAXIOV 1024`` in ``linux/uio.h``, with no sysctl and no
        ``/proc`` entry. So there is nothing to query and nothing to set; this
        is the only knob that exists. Raise it if you gather more than 1024
        buffers per call and want them in one syscall.
    :returns: the names added or removed by this call.
    :raises ValueError: for an ``iov_max`` below 1.
    """
    changed: "List[str]" = []

    if not enable:
        # Reset the tunable too: leaving a previous call's iov_max in place
        # would make a later re-install silently inherit it.
        _SYSCONF_VALUES["SC_IOV_MAX"] = _IOV_MAX
        for name in list(_installed):
            target, attribute = _installed.pop(name)
            try:
                delattr(target, attribute)
            except AttributeError:  # pragma: no cover - already gone
                pass
            changed.append(name)
        return changed

    if not has_recvmsg():
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

    # `os.sysconf` is part of this patch, not a separate feature: it is needed
    # only because installing `sendmsg` above makes the stdlib's
    # "sendmsg implies POSIX implies os.sysconf" inference wrong. Installing and
    # removing them together is what keeps that coupling honest -- see
    # `_shim_sysconf`.
    if iov_max is not None:
        if iov_max < 1:
            raise ValueError("iov_max must be at least 1, got %r" % (iov_max,))
        _SYSCONF_VALUES["SC_IOV_MAX"] = int(iov_max)
        if "os.sysconf_names" in _installed:
            # Keep the advertised table in step with what sysconf answers.
            _os.sysconf_names.update(_SYSCONF_VALUES)  # type: ignore[attr-defined]

    if "os.sysconf" not in _installed and not hasattr(_os, "sysconf"):
        setattr(_os, "sysconf", _shim_sysconf)
        _installed["os.sysconf"] = (_os, "sysconf")
        changed.append("os.sysconf")
        if not hasattr(_os, "sysconf_names"):
            setattr(_os, "sysconf_names", dict(_SYSCONF_VALUES))
            _installed["os.sysconf_names"] = (_os, "sysconf_names")
            changed.append("os.sysconf_names")

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
    """Bound-method form of :func:`recvmsg`, installed on :class:`socket.socket`.

    **Reshapes the ancillary data into the POSIX field order**, unlike
    :func:`recvmsg`, which reports the platform's own bytes. See
    :func:`_to_posix_shape`: this method only exists on platforms where it
    natively would not, so code reaching for it is POSIX-shaped code, and giving
    it the name without the layout is the half-impersonation that makes such
    code misparse.
    """
    data, ancdata, msg_flags, address = recvmsg(self, bufsize, ancbufsize, flags)
    return data, _to_posix_shape(ancdata), msg_flags, address


def _patched_sendmsg(
    self: "Any",
    buffers: "Sequence[bytes]",
    ancdata: "Iterable[Tuple[int, int, bytes]]" = (),
    flags: int = 0,
    address: "Optional[Any]" = None,
) -> int:
    """Bound-method form of :func:`sendmsg`, installed on :class:`socket.socket`.

    Accepts a POSIX-shaped ``in_pktinfo`` as well as the native one, chosen by
    length -- see :func:`_from_posix_shape`. The counterpart to the reshaping
    the patched :meth:`recvmsg` does, so a caller can round-trip what it
    received.
    """
    return sendmsg(self, buffers, _from_posix_shape(ancdata), flags, address)


def _patch_requested() -> bool:
    """Whether the import-time patch is wanted.

    Read once, at import. ``NETIMPS_SOCKET_PATCH`` unset or empty means yes;
    ``1``, ``true``, ``yes``, ``on`` mean yes and ``0``, ``false``, ``no``,
    ``off`` mean no, in any case. Anything else raises :class:`ValueError`
    naming the variable: a typo must not read as a choice.

    ``NETIMPS_NO_SOCKET_PATCH`` set to anything raises as well. That name has
    the opposite sense, so honouring it is impossible and ignoring it would
    install the patch for someone who had asked for it to be left out.
    """
    if "NETIMPS_NO_SOCKET_PATCH" in _os.environ:
        raise ValueError(
            "NETIMPS_NO_SOCKET_PATCH is no longer supported. "
            "Use NETIMPS_SOCKET_PATCH=0 to disable the patch."
        )
    value = _os.environ.get("NETIMPS_SOCKET_PATCH", "").strip().lower()
    if value in ("", "1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise ValueError(
        "NETIMPS_SOCKET_PATCH must be one of 1/true/yes/on or 0/false/no/off, "
        "got %r" % (_os.environ["NETIMPS_SOCKET_PATCH"],)
    )
