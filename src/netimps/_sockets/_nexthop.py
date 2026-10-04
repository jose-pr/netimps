"""Reading the first hop from each platform's routing table."""

from __future__ import annotations

import socket as _socket
import struct as _struct
from typing import Optional, Tuple
from .. import _proc
from .._ip import LOOPBACK_V4, LOOPBACK_V6
from .._parse import try_parse

#: Seconds ``route -n get`` may run on the BSDs before the next hop is reported
#: as unknown. It answers from the kernel's table and returns at once.
_ROUTE_TIMEOUT_SECONDS = 5.0


#: ``(gateway_or_None, interface_index)``. A ``None`` gateway means *on-link*;
#: a ``None`` in place of the whole tuple means the lookup could not be made,
#: which is a different answer and the one :attr:`Route.on_link` reports as
#: ``None`` rather than as ``True``.
_NextHop = Tuple[Optional[str], int]


def _windows_next_hop(dest: str, ipv6: bool = False) -> "Optional[_NextHop]":
    """Next hop from ``GetBestRoute2``. Both address families.

    ``GetBestRoute2`` rather than ``GetIpForwardTable``: it asks Windows which
    route *it* would choose for a destination, so the kernel does the
    longest-prefix matching. Dumping the table and matching by hand -- which is
    what the POSIX side has to do, lacking an equivalent -- is more code and
    more ways to be wrong. It supersedes ``GetBestRoute``, which takes a packed
    IPv4 address and therefore cannot answer for IPv6 at all; this one takes a
    ``SOCKADDR_INET`` and handles both.

    Returns ``None`` when Windows reports no route (``ERROR_NETWORK_UNREACHABLE``
    for a v6 destination on a v4-only host, for instance) -- not "on-link".
    """
    import ctypes
    from ctypes import wintypes

    class _SOCKADDR_IN(ctypes.Structure):
        _fields_ = [
            ("sin_family", ctypes.c_ushort),
            ("sin_port", ctypes.c_ushort),
            ("sin_addr", ctypes.c_ubyte * 4),
            ("sin_zero", ctypes.c_ubyte * 8),
        ]

    class _SOCKADDR_IN6(ctypes.Structure):
        _fields_ = [
            ("sin6_family", ctypes.c_ushort),
            ("sin6_port", ctypes.c_ushort),
            ("sin6_flowinfo", wintypes.ULONG),
            ("sin6_addr", ctypes.c_ubyte * 16),
            ("sin6_scope_id", wintypes.ULONG),
        ]

    class _SOCKADDR_INET(ctypes.Union):
        _fields_ = [
            ("Ipv4", _SOCKADDR_IN),
            ("Ipv6", _SOCKADDR_IN6),
            ("si_family", ctypes.c_ushort),
        ]

    class _IP_ADDRESS_PREFIX(ctypes.Structure):
        _fields_ = [("Prefix", _SOCKADDR_INET), ("PrefixLength", ctypes.c_ubyte)]

    class _MIB_IPFORWARD_ROW2(ctypes.Structure):
        _fields_ = [
            ("InterfaceLuid", ctypes.c_ulonglong),
            ("InterfaceIndex", wintypes.ULONG),
            ("DestinationPrefix", _IP_ADDRESS_PREFIX),
            ("NextHop", _SOCKADDR_INET),
            ("SitePrefixLength", ctypes.c_ubyte),
            ("ValidLifetime", wintypes.ULONG),
            ("PreferredLifetime", wintypes.ULONG),
            ("Metric", wintypes.ULONG),
            ("Protocol", ctypes.c_int),
            ("Loopback", ctypes.c_ubyte),
            ("AutoconfigureAddress", ctypes.c_ubyte),
            ("Publish", ctypes.c_ubyte),
            ("Immortal", ctypes.c_ubyte),
            ("Age", wintypes.ULONG),
            ("Origin", ctypes.c_int),
        ]

    family = _socket.AF_INET6 if ipv6 else _socket.AF_INET
    packed = _socket.inet_pton(family, dest)

    destination = _SOCKADDR_INET()
    if ipv6:
        destination.Ipv6.sin6_family = family
        ctypes.memmove(destination.Ipv6.sin6_addr, packed, 16)
    else:
        destination.Ipv4.sin_family = family
        ctypes.memmove(destination.Ipv4.sin_addr, packed, 4)

    iphlpapi = ctypes.WinDLL("iphlpapi.dll")  # type: ignore[attr-defined]  # Windows-only name; mypy checks this branch on every platform, and it is already guarded at runtime
    row = _MIB_IPFORWARD_ROW2()
    best_source = _SOCKADDR_INET()
    status = iphlpapi.GetBestRoute2(
        None,  # InterfaceLuid: let Windows choose
        0,  # InterfaceIndex
        None,  # SourceAddress
        ctypes.byref(destination),
        0,  # AddressSortOptions
        ctypes.byref(row),
        ctypes.byref(best_source),
    )
    if status != 0:
        return None

    hop = row.NextHop
    if hop.si_family == _socket.AF_INET6:
        text = _socket.inet_ntop(_socket.AF_INET6, bytes(hop.Ipv6.sin6_addr))
        unspecified = "::"
    elif hop.si_family == _socket.AF_INET:
        text = _socket.inet_ntop(_socket.AF_INET, bytes(hop.Ipv4.sin_addr))
        unspecified = "0.0.0.0"
    else:
        return None
    # The unspecified address means "on-link" -- no router in the path.
    return (None if text == unspecified else text), int(row.InterfaceIndex)


#: ``/proc/net/ipv6_route`` flag bits. ``RTF_UP`` is not decoration: the
#: unreachable ``::/0`` route the kernel keeps on ``lo`` has it **clear** and
#: ``RTF_REJECT`` set, and matching it would report every global IPv6
#: destination as on-link via loopback. Measured on WSL2.
_RTF_UP = 0x0001
_RTF_REJECT = 0x0200


def _posix_next_hop(dst: str, ipv6: bool = False) -> "Optional[_NextHop]":
    """Next hop by reading the kernel routing table. Linux only.

    ``/proc/net/route`` for IPv4 and ``/proc/net/ipv6_route`` for IPv6. The
    two formats share nothing but the idea: v4 is hex little-endian words
    behind a header line, v6 is big-endian hex nibbles with no header and an
    explicit prefix length.

    Returns ``None`` when neither file can be read (every non-Linux platform,
    which is what :func:`_bsd_next_hop` is for) or nothing matched, so the
    caller can report "unknown" instead of inventing "on-link".
    """
    if ipv6:
        return _posix_next_hop_v6(dst)

    try:
        with open("/proc/net/route") as handle:
            lines = handle.read().splitlines()
    except OSError:
        return None

    # /proc/net/route omits loopback entirely on many kernels, so a lookup for
    # 127.0.0.1 would fall through to the default route (mask 0) and report the
    # LAN gateway. Loopback is on-link by definition; answer it directly.

    parsed_dest = try_parse(dst)
    if parsed_dest is not None and parsed_dest in LOOPBACK_V4:
        return None, _if_index("lo")

    try:
        packed = _struct.unpack("<I", _socket.inet_aton(dst))[0]
    except (OSError, _struct.error):
        return None

    best = None
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 8:
            continue
        try:
            destination = int(parts[1], 16)
            gateway = int(parts[2], 16)
            mask = int(parts[7], 16)
        except ValueError:
            continue
        if (packed & mask) == destination:
            # Longest prefix wins, so prefer the most specific match.
            ones = bin(mask).count("1")
            if best is None or ones > best[0]:
                best = (ones, gateway, parts[0])

    if best is None:
        return None
    _, gateway, name = best
    if gateway == 0:
        return None, _if_index(name)
    return _socket.inet_ntoa(_struct.pack("<I", gateway)), _if_index(name)


def _parse_ipv6_route_table(text: str, dst: str) -> "Optional[_NextHop]":
    """Longest-prefix match ``dst`` against ``/proc/net/ipv6_route`` text.

    Split out from the file read so it is testable offline against a captured
    table.

    Columns, none of them labelled: destination, prefix length, source, source
    prefix length, next hop, metric, refcount, use, flags, device.
    """
    try:
        packed = int.from_bytes(_socket.inet_pton(_socket.AF_INET6, dst), "big")
    except OSError:
        return None

    best = None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            destination = int(parts[0], 16)
            prefix_length = int(parts[1], 16)
            gateway = int(parts[4], 16)
            flags = int(parts[8], 16)
        except ValueError:
            continue
        if prefix_length > 128:
            continue
        if not flags & _RTF_UP or flags & _RTF_REJECT:
            continue
        shift = 128 - prefix_length
        if (packed >> shift) != (destination >> shift):
            continue
        if best is None or prefix_length > best[0]:
            best = (prefix_length, gateway, parts[9])

    if best is None:
        return None
    _, gateway, name = best
    if gateway == 0:
        return None, _if_index(name)
    text_hop = _socket.inet_ntop(_socket.AF_INET6, gateway.to_bytes(16, "big"))
    return text_hop, _if_index(name)


def _posix_next_hop_v6(dst: str) -> "Optional[_NextHop]":
    try:
        with open("/proc/net/ipv6_route") as handle:
            table = handle.read()
    except OSError:
        return None
    return _parse_ipv6_route_table(table, dst)


def _parse_route_get_output(text: str) -> "Optional[_NextHop]":
    """Read ``route -n get <dst>`` output (BSD/macOS). Both families.

    Only the ``gateway:`` and ``interface:`` lines are read, never the prose
    or the flags block::

           route to: 1.1.1.1
        destination: default
            gateway: 192.168.64.1
          interface: en0

    A ``gateway:`` that does not parse as an address is the BSD ``link#4``
    spelling, which *is* the on-link answer -- as is no ``gateway:`` line at
    all. Returns ``None`` only when there is no ``interface:`` either, i.e.
    when nothing was matched.
    """

    gateway = None
    name = None
    for line in text.splitlines():
        label, sep, value = line.partition(":")
        if not sep:
            continue
        label = label.strip()
        value = value.strip()
        if label == "gateway" and try_parse(value) is not None:
            gateway = value
        elif label == "interface":
            name = value
    if gateway is None and name is None:
        return None
    return gateway, _if_index(name) if name else 0


def _bsd_next_hop(dst: str, ipv6: bool = False) -> "Optional[_NextHop]":
    """Next hop from ``route -n get``, the BSD unprivileged equivalent.

    macOS and the BSDs have no ``/proc``, so :func:`_posix_next_hop` finds
    nothing there; without this, ``get_route`` would report ``gateway=None``
    for every destination. ``route -n get`` answers the same question the
    kernel answers, unprivileged.

    ``-n`` keeps the output numeric, so nothing here depends on reverse DNS,
    and ``stdin`` is ``DEVNULL`` because a library must never consume its
    caller's. Any failure is ``None``: unknown, not on-link.
    """

    # Loopback is on-link by definition, so answer it without spawning
    # anything -- and without depending on how this platform's `route` chooses
    # to spell a host route, which is the one shape not measured here.
    parsed = try_parse(dst)
    if parsed is not None and parsed in (LOOPBACK_V6 if ipv6 else LOOPBACK_V4):
        return None, 0

    command = ["route", "-n", "get"]
    if ipv6:
        command.append("-inet6")
    command.append(dst)
    try:
        result = _proc.run(command[0], command[1:], timeout=_ROUTE_TIMEOUT_SECONDS)
    except (OSError, ValueError):
        return None
    if result.returncode != 0:
        return None
    return _parse_route_get_output(result.stdout)


def _if_index(name: str) -> int:
    try:
        return _socket.if_nametoindex(name)
    except (OSError, AttributeError, ValueError):
        return 0
