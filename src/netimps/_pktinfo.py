"""PKTINFO constants, layouts and decoding, shared by the UDP and messaging code (internal)."""

from __future__ import annotations

import socket as _socket
import struct as _struct
import sys as _sys
from typing import Optional, Tuple

from ._ip import IPAddress
from ._parse import try_parse

_IS_WINDOWS = _sys.platform == "win32"


#: Documented kernel ABI values, used when CPython does not export the name.
#:
#: **``socket.IP_PKTINFO`` only arrived in CPython 3.12.** On 3.9, 3.10 and 3.11
#: it is absent on *every* platform, so a bare ``getattr`` left IPv4 pktinfo --
#: the arrival-interface feature this module exists for -- silently off for half
#: the supported interpreter range, on Linux and macOS as well as Windows.
#: Measured on the CI matrix: 3.9/3.10/3.11 failed the pinning test while
#: 3.12/3.13/3.14 passed, with the platform held constant.
#:
#: These are stable parts of each kernel's ABI, not guesses -- every value here
#: was read back from a live socket by `.github/probe/capture.py` -- and the repo
#: rule for exactly this case is to use the literal and let ``OSError`` from
#: ``setsockopt`` be the real "unsupported" signal. There is no single literal
#: because the three platforms genuinely disagree.
#:
#: ``(IP_PKTINFO, IPV6_PKTINFO, IPV6_RECVPKTINFO)``; ``None`` where the platform
#: has no such option at all.
#: Declared before the branches so mypy does not type the tuple from whichever
#: platform it happens to be checking as the target.
_PKTINFO_FALLBACK: "Tuple[Optional[int], Optional[int], Optional[int]]"

if _IS_WINDOWS:
    # IPV6_PKTINFO is both the request and the carrier here; there is no
    # IPV6_RECVPKTINFO.
    _PKTINFO_FALLBACK = (19, 19, None)
elif _sys.platform.startswith("linux"):
    _PKTINFO_FALLBACK = (8, 50, 49)
elif _sys.platform.startswith("freebsd"):
    # No IPv4 IP_PKTINFO (errno 42): `_freebsd` carries IPv4 there. IPv6 uses
    # the same options as macOS.
    _PKTINFO_FALLBACK = (None, 46, 61)
elif _sys.platform == "darwin" or "bsd" in _sys.platform:
    # macOS really does have IP_PKTINFO (26), with Linux's exact 12-byte layout.
    # The widespread "BSD has no IP_PKTINFO, use IP_RECVDSTADDR + IP_RECVIF"
    # advice is out of date for Darwin, and was measured wrong on a runner.
    _PKTINFO_FALLBACK = (26, 46, 61)
else:  # pragma: no cover - an unmeasured platform gets no guesses
    _PKTINFO_FALLBACK = (None, None, None)

#: Probed per family, because a platform can have one and not the other.
_IP_PKTINFO = getattr(_socket, "IP_PKTINFO", None) or _PKTINFO_FALLBACK[0]
_IPV6_PKTINFO = getattr(_socket, "IPV6_PKTINFO", None) or _PKTINFO_FALLBACK[1]
_IPV6_RECVPKTINFO = getattr(_socket, "IPV6_RECVPKTINFO", None) or _PKTINFO_FALLBACK[2]


#: ``struct in_pktinfo``, and it is **not one layout across platforms** -- the
#: field order differs, not merely the size, so a single string cannot serve
#: both. Native byte order; this never leaves the host.
#:
#: - POSIX ``in_pktinfo``: ``{ipi_ifindex; ipi_spec_dst; ipi_addr}``, 12 bytes.
#: - Windows ``IN_PKTINFO``: ``{ipi_addr; ipi_ifindex}``, 8 bytes, and there is
#:   no ``spec_dst`` at all.
#:
#: Measured 2026-10-02 on loopback: Linux delivered ``cmsg_type`` 8 with 12
#: bytes, Windows ``cmsg_type`` 19 with 8 bytes. Parsing one with the other's
#: layout does not raise -- it yields a *plausible wrong address* and index 0,
#: which is exactly the failure this table exists to prevent.
_PKTINFO_V4_WINDOWS = "=4sI"
_PKTINFO_V4_POSIX = "=I4s4s"
_PKTINFO_V4 = _PKTINFO_V4_WINDOWS if _IS_WINDOWS else _PKTINFO_V4_POSIX

#: Whether :data:`_PKTINFO_V4` puts the address before the index. Kept as its
#: own flag because the struct string alone cannot tell the unpacker which
#: field it is looking at.
_PKTINFO_V4_ADDR_FIRST = _IS_WINDOWS

#: ``struct in6_pktinfo``: the 16-byte address **first**, then the interface
#: index. The opposite field order from ``in_pktinfo``, which is why the two
#: cannot share one layout string.
_PKTINFO_V6 = "=16sI"

#: Cmsg types that carry pktinfo, per level. ``IPV6_RECVPKTINFO`` is matched
#: alongside ``IPV6_PKTINFO`` because the two are distinct constants on Linux
#: (49 and 50) and need not be everywhere; accepting both costs nothing and
#: survives a platform that gives them one value.
_V4_PKTINFO_TYPES = frozenset(t for t in (_IP_PKTINFO,) if t is not None)
_V6_PKTINFO_TYPES = frozenset(
    t for t in (_IPV6_PKTINFO, _IPV6_RECVPKTINFO) if t is not None
)


def _pktinfo_options(family: int) -> "Tuple[int, Optional[int], Optional[int], str]":
    """``(level, receive option, send cmsg type, struct layout)`` for *family*.

    The receive option and the send cmsg type are the *same* constant for
    IPv4 and two *different* ones for IPv6 on POSIX (``IPV6_RECVPKTINFO``
    requests the data, ``IPV6_PKTINFO`` carries it), so they are returned
    separately rather than collapsed into one "the option" value.

    **Windows has no ``IPV6_RECVPKTINFO`` at all**: there ``IPV6_PKTINFO`` (19)
    is both the request and the carrier, and setting it is what enables receipt.
    Asking only for ``IPV6_RECVPKTINFO`` therefore finds ``None`` and silently
    turns IPv6 pktinfo off on Windows -- measured on a CI runner, where
    ``UDPEndpoint(bind("::", 0)).has_pktinfo`` was ``False`` while a raw
    ``recvmsg`` on the same socket delivered the cmsg perfectly well. Hence the
    fallback below is explicit.

    Either may be ``None`` where the platform exports neither; the caller
    turns that into a ``supports_*`` flag rather than an error.
    """
    if family == _socket.AF_INET6:
        receive = _IPV6_RECVPKTINFO if _IPV6_RECVPKTINFO is not None else _IPV6_PKTINFO
        return _socket.IPPROTO_IPV6, receive, _IPV6_PKTINFO, _PKTINFO_V6
    return _socket.IPPROTO_IP, _IP_PKTINFO, _IP_PKTINFO, _PKTINFO_V4


def _unpack_pktinfo(
    level: int, ctype: int, cdata: bytes
) -> "Optional[Tuple[int, Optional[IPAddress]]]":
    """Decode one ancillary message into ``(interface index, local address)``.

    Dispatches on ``cmsg_level`` rather than assuming the socket's family, so
    a dual-stack socket -- or one the caller has configured further -- is read
    correctly instead of being unpacked with the wrong layout.

    Returns ``None`` for anything that is not pktinfo, and for a pktinfo cmsg
    too short to be one: a truncated struct is treated as absent rather than
    guessed at, and the caller keeps scanning the remaining messages.
    """

    if level == _socket.IPPROTO_IP and ctype in _V4_PKTINFO_TYPES:
        size = _struct.calcsize(_PKTINFO_V4)
        if len(cdata) < size:
            return None
        fields = _struct.unpack(_PKTINFO_V4, cdata[:size])
        if _PKTINFO_V4_ADDR_FIRST:
            destination, index = fields
        else:
            index, _local_if, destination = fields
        return int(index), try_parse(destination)

    if level == _socket.IPPROTO_IPV6 and ctype in _V6_PKTINFO_TYPES:
        size = _struct.calcsize(_PKTINFO_V6)
        if len(cdata) < size:
            return None
        destination, index = _struct.unpack(_PKTINFO_V6, cdata[:size])
        return int(index), try_parse(destination)

    return None
