"""IPv4 arrival data and source pinning on FreeBSD (internal).

FreeBSD has no IPv4 ``IP_PKTINFO``: ``setsockopt`` for it fails with ``ENOPROTOOPT``
(errno 42). It reports the same facts through three options, none of which
CPython exports under a usable name (3.11 exports only ``IP_RECVDSTADDR``), so
the literals are here. Measured on FreeBSD 16.0, 2026-10-04, loopback only:

=================  ====  =============================================
use                 no.  message
=================  ====  =============================================
``IP_RECVDSTADDR``    7  receive: ``(IPPROTO_IP, 7, 4-byte address)``
``IP_RECVIF``        20  receive: ``(IPPROTO_IP, 20, sockaddr_dl)``
``IP_SENDSRCADDR``    7  send: ``(IPPROTO_IP, 7, 4-byte address)``
=================  ====  =============================================

``sockaddr_dl`` is 56 bytes there: ``sdl_len`` and ``sdl_family`` (18, ``AF_LINK``)
bytes, then ``sdl_index`` as a native-endian ``u16`` at offset 2, the name length
at offset 5 and the interface name from offset 8.

The send message pins the source only on a socket **bound to the wildcard and not
connected**; on a socket bound to one address, or connected, it fails with errno
22. A source that is not local fails with errno 49. There is no IPv4 way to choose
the outgoing interface by index, so an interface is pinned by its address.

IPv6 on FreeBSD uses the same options as everywhere else and is not handled here.
"""

from __future__ import annotations

import socket as _socket
import struct as _struct
import sys as _sys
from typing import Any, Optional, Tuple

from ._ip import IPv4Address

__all__ = ["IS_FREEBSD"]

#: Read at call time by :mod:`netimps._udp`, so a test can switch it.
IS_FREEBSD = _sys.platform.startswith("freebsd")

IP_RECVDSTADDR = 7
IP_RECVIF = 20
IP_SENDSRCADDR = 7

#: ``AF_LINK``: the family of the ``sockaddr_dl`` that ``IP_RECVIF`` delivers.
AF_LINK = 18


def parse_sockaddr_dl(data: bytes) -> "Optional[Tuple[int, str]]":
    """``(interface index, interface name)`` from a ``sockaddr_dl``, else ``None``.

    ``None`` for anything shorter than the fixed header, of another family, or
    whose name runs past the data: a truncated structure is treated as absent
    rather than guessed at.
    """
    if len(data) < 8 or data[1] != AF_LINK:
        return None
    (index,) = _struct.unpack_from("=H", data, 2)
    name_length = data[5]
    name = data[8 : 8 + name_length]
    if len(name) != name_length:
        return None
    return int(index), name.decode("ascii", "replace")


def decode_arrival(
    level: int, ctype: int, cdata: bytes
) -> "Optional[Tuple[int, Optional[IPv4Address]]]":
    """One received control message as ``(interface index, address)``.

    The index is ``0`` for the destination-address message and the address is
    ``None`` for the interface message; ``None`` for any other message.
    """
    if level != _socket.IPPROTO_IP:
        return None
    if ctype == IP_RECVDSTADDR and len(cdata) >= 4:
        return 0, IPv4Address(bytes(cdata[:4]))
    if ctype == IP_RECVIF:
        parsed = parse_sockaddr_dl(cdata)
        if parsed is not None:
            return parsed[0], None
    return None


def source_control(address: "IPv4Address") -> "Tuple[int, int, bytes]":
    """The send control message that pins the source address to *address*."""
    return _socket.IPPROTO_IP, IP_SENDSRCADDR, address.packed


def enable_receive(sock: "Any") -> bool:
    """Ask *sock* for the destination address and the arrival interface.

    ``True`` when the address is delivered. The interface option is best effort:
    without it the address still arrives and the interface index is ``0``.
    """
    try:
        sock.setsockopt(_socket.IPPROTO_IP, IP_RECVDSTADDR, 1)
    except OSError:
        return False
    try:
        sock.setsockopt(_socket.IPPROTO_IP, IP_RECVIF, 1)
    except OSError:
        pass
    return True


def can_pin(sock: "Any") -> bool:
    """Whether a source can be pinned on *sock*: bound to the wildcard address."""
    try:
        return str(sock.getsockname()[0]) in ("0.0.0.0", "")
    except (OSError, IndexError, TypeError):
        return False
