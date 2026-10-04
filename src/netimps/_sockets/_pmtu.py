"""The kernel's cached path MTU, the negotiated TCP MSS, and the don't-fragment option."""

from __future__ import annotations

import socket as _socket
import struct as _struct
import sys as _sys
from typing import Any, List, Optional, Tuple
from .._ip import HostLike, _dst_argument
from .._scheme import coerce_port as _coerce_port
from ._connect import _connect_timeout, _resolve_targets

_IS_WINDOWS = _sys.platform == "win32"
_IS_LINUX = _sys.platform.startswith("linux")


# Socket options CPython does not export, named here from the platform
# headers. ``getattr`` is still tried first at every use, so a future CPython
# that does export one wins; these are the fallback, and they are guarded --
# a wrong number surfaces as ``OSError`` from ``setsockopt``, which the
# callers read as "DF unavailable" rather than as a measurement.
#
# Measured 2026-09-20: ``socket.IP_MTU``, ``IP_MTU_DISCOVER`` and
# ``IP_PMTUDISC_DO`` are absent on **every** platform including Linux (3.13
# and 3.14), so a ``getattr(socket, "IP_MTU", None)`` guard disables the code
# that reads or sets them everywhere. ``IPV6_PATHMTU``/``IPV6_DONTFRAG`` *are*
# exported on Linux.
_LINUX_IP_MTU = 14  # <linux/in.h>
_LINUX_IP_MTU_DISCOVER = 10  # <linux/in.h>
_LINUX_IP_PMTUDISC_DO = 2  # <linux/in.h>
_LINUX_IPV6_MTU_DISCOVER = 23  # <linux/in6.h>
_LINUX_IPV6_PMTUDISC_DO = 2  # <linux/in6.h>
_WINDOWS_IP_DONTFRAGMENT = 14  # <ws2ipdef.h>
#: The BSDs do not agree with each other here: FreeBSD's `IP_DONTFRAG` is 67,
#: Darwin's is 28, and a `setsockopt` with the wrong one simply fails -- which,
#: for a DF option, means the MTU search silently loses its whole point (on
#: macOS `_set_dont_fragment` returns False with the FreeBSD value).
_DARWIN_IP_DONTFRAG = 28  # <netinet/in.h>, Darwin
_FREEBSD_IP_DONTFRAG = 67  # <netinet/in.h>, FreeBSD
_BSD_IP_DONTFRAG = (
    _DARWIN_IP_DONTFRAG if _sys.platform == "darwin" else _FREEBSD_IP_DONTFRAG
)
#: This one they do agree on: the RFC 3542 number, same on Darwin and FreeBSD.
_BSD_IPV6_DONTFRAG = 62  # <netinet6/in6.h>


def _option(name: str, fallback: int) -> int:
    """``socket.<name>`` if CPython exports it, else the header literal.

    Written this way round on purpose: the literal is a fact about the
    platform's headers, not about CPython, so a future release that starts
    exporting the constant silently takes over.
    """
    value = getattr(_socket, name, None)
    return fallback if value is None else int(value)


def _dont_fragment_options(family: int) -> "List[Tuple[int, int, int]]":
    """``(level, option, value)`` triples that stop local fragmentation.

    Four spellings for one idea, and **none of them is portable**: Linux uses
    ``IP_MTU_DISCOVER = IP_PMTUDISC_DO`` (which also asks the kernel to *learn*
    the path MTU), the BSDs ``IP_DONTFRAG``, Windows ``IP_DONTFRAGMENT``, and
    each has an ``IPV6_`` counterpart at a different level. Setting none of
    them does not fail: the stack
    fragments the probe, the peer reassembles it and answers, every size
    "survives", and the binary search confidently returns its own ceiling.
    """
    if family == _socket.AF_INET6:
        level = _socket.IPPROTO_IPV6
        if _IS_LINUX:
            return [
                (
                    level,
                    _option("IPV6_MTU_DISCOVER", _LINUX_IPV6_MTU_DISCOVER),
                    _option("IPV6_PMTUDISC_DO", _LINUX_IPV6_PMTUDISC_DO),
                )
            ]
        return [(level, _option("IPV6_DONTFRAG", _BSD_IPV6_DONTFRAG), 1)]

    level = _socket.IPPROTO_IP
    if _IS_LINUX:
        return [
            (
                level,
                _option("IP_MTU_DISCOVER", _LINUX_IP_MTU_DISCOVER),
                _option("IP_PMTUDISC_DO", _LINUX_IP_PMTUDISC_DO),
            )
        ]
    if _IS_WINDOWS:
        return [(level, _option("IP_DONTFRAGMENT", _WINDOWS_IP_DONTFRAGMENT), 1)]
    return [(level, _option("IP_DONTFRAG", _BSD_IP_DONTFRAG), 1)]


def _set_dont_fragment(sock: "_socket.socket", family: int) -> bool:
    """Set DF on ``sock``; ``False`` if this platform will not take it.

    A ``False`` here is the caller's cue to answer ``None`` rather than a
    number: an MTU search without DF measures nothing.
    """
    try:
        for level, option, value in _dont_fragment_options(family):
            sock.setsockopt(level, option, value)
    except OSError:
        return False
    return True


#: ``struct ip6_mtuinfo``: a ``sockaddr_in6`` (28 bytes on every supported
#: platform) followed by the MTU as a native ``uint32``. ``IPV6_PATHMTU``
#: returns *this*, not the bare int the IPv4 ``IP_MTU`` gives back -- reading
#: it as an int would decode the address family as the MTU.
_IP6_MTUINFO_SIZE = 32
_IP6_MTUINFO_MTU_OFFSET = 28


def _pmtu_for(family: int, sockaddr: Any) -> "Optional[int]":
    """The kernel's cached path MTU for one resolved target, or ``None``."""
    if family == _socket.AF_INET6:
        level = _socket.IPPROTO_IPV6
        # Exported by CPython on Linux (61) but not on Windows, which has no
        # equivalent at all -- so no literal fallback here.
        option = getattr(_socket, "IPV6_PATHMTU", None)
    else:
        level = _socket.IPPROTO_IP
        option = getattr(_socket, "IP_MTU", None)
        if option is None and _IS_LINUX:
            option = _LINUX_IP_MTU
    if option is None:
        return None

    try:
        sock = _socket.socket(family, _socket.SOCK_DGRAM)
    except OSError:
        return None
    try:
        # PMTU is only maintained for connected sockets in DO mode.
        _set_dont_fragment(sock, family)
        sock.connect(sockaddr)
        if family == _socket.AF_INET6:
            raw = sock.getsockopt(level, option, _IP6_MTUINFO_SIZE)
            if len(raw) < _IP6_MTUINFO_SIZE:
                return None
            value = int(_struct.unpack_from("=I", raw, _IP6_MTUINFO_MTU_OFFSET)[0])
        else:
            value = int(sock.getsockopt(level, option))
        return value if value > 0 else None
    except (OSError, OverflowError, _struct.error):
        return None
    finally:
        sock.close()


def get_pmtu(
    dst: "HostLike", port: int = 80, *, ipv6: "Optional[bool]" = None
) -> "Optional[int]":
    """Return the path MTU the kernel has **already learned**, or ``None``.

    A lookup, not a measurement -- it reads ``IP_MTU`` (or ``IPV6_PATHMTU``) on
    a connected socket and sends nothing::

        get_pmtu("example.com")      # 1420, or None if nothing is cached

    ``dst`` also accepts an address object or an :class:`IPv4Interface`/
    :class:`IPv6Interface` (its ``.ip`` is used); ``ipv6=`` picks which family
    a hostname is resolved to.

    Instant and silent, but it answers a weaker question than
    :func:`discover_mtu`:

    * **``None`` is a common answer.** The kernel only knows a path MTU once
      its own discovery has learned one, which needs prior traffic that
      actually hit the limit. A fresh destination may report nothing.
    * **Windows has no ``IP_MTU``** (nor ``IP_MTU_DISCOVER`` / ``IPV6_PATHMTU``),
      so this always returns ``None`` there. Nor is there another route: the
      ``dwForwardMtu`` field of ``MIB_IPFORWARDROW`` reads **0** (verified via
      ``GetBestRoute``; Microsoft lists it as unsupported), and the newer
      ``MIB_IPFORWARD_ROW2`` dropped the field entirely. Route MTU lives at the
      interface level on Windows, which is :attr:`Interface.mtu`. Probing with
      :func:`discover_mtu` is the only way to learn a *path* MTU there.
    * macOS/BSD expose no IPv4 equivalent either, so v4 there is ``None`` too.
    * When the kernel *has* an answer it can still be the **local link** MTU
      rather than the path minimum, if nothing has yet forced it lower.

    .. note::
       ``IP_MTU``, ``IP_MTU_DISCOVER`` and ``IP_PMTUDISC_DO`` are **not
       exported by CPython on any platform**, Linux included (measured on 3.13
       and 3.14). Guarding on ``getattr(socket, "IP_MTU", None)`` therefore
       made this function unreachable everywhere rather than on Windows only,
       which is what the "usually ``None``" story was hiding. The Linux
       numbers are named from ``<linux/in.h>`` instead.

    Use it as a free first guess; use :func:`discover_mtu` when the answer has
    to be right.
    """
    dst = _dst_argument(dst)
    port = _coerce_port(port)
    for family, sockaddr in _resolve_targets(dst, port, ipv6, _socket.SOCK_DGRAM):
        value = _pmtu_for(family, sockaddr)
        if value is not None:
            return value
    return None


def _tcp_mss(
    dst: str, port: int, timeout: float, ipv6: "Optional[bool]"
) -> "Optional[Tuple[int, int]]":
    """``(mss, family)`` of the first connection to ``dst`` that succeeds."""
    option = getattr(_socket, "TCP_MAXSEG", None)
    if option is None:
        return None
    for family, sockaddr in _resolve_targets(dst, port, ipv6, _socket.SOCK_STREAM):
        try:
            sock = _socket.socket(family, _socket.SOCK_STREAM)
        except OSError:
            continue
        sock.settimeout(_connect_timeout(timeout))
        try:
            sock.connect(sockaddr)
            value = int(sock.getsockopt(_socket.IPPROTO_TCP, option))
            if value > 0:
                return value, family
        except (OSError, OverflowError, ValueError):
            continue
        finally:
            sock.close()
    return None


def get_tcp_mss(
    dst: "HostLike",
    port: int,
    *,
    timeout: float = 3.0,
    ipv6: "Optional[bool]" = None,
) -> "Optional[int]":
    """Return the TCP maximum segment size negotiated with ``dst``, or ``None``.

    The TCP counterpart to an MTU: the largest payload a single segment may
    carry, agreed during the handshake::

        get_tcp_mss("example.com", 443)     # 1460 on a 1500-MTU path

    ``dst`` also accepts an address object or an :class:`IPv4Interface`/
    :class:`IPv6Interface` (its ``.ip`` is used). ``ipv6=`` picks which family
    a hostname is connected over; a destination of the other family gives
    ``None``.

    This **opens a real connection** to read the value, then closes it.

    MSS is normally the path MTU minus 40 (20 IPv4 + 20 TCP), so a reduced
    value is a useful signal: a VPN or tunnel is shrinking the path. Measured
    on one host: 1412 over a VPN where the link MTU was 1500, and 32741 on
    loopback.

    Returns ``None`` where the platform does not expose ``TCP_MAXSEG`` or the
    connection fails. Note this is what the *kernels agreed*, not what a
    middlebox further along will actually pass -- for that, measure with
    :func:`discover_mtu`.
    """
    dst = _dst_argument(dst)
    port = _coerce_port(port)
    measured = _tcp_mss(dst, port, timeout, ipv6)
    return None if measured is None else measured[0]
