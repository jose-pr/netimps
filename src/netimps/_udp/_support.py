"""Whether this host can report a datagram's arrival interface (internal)."""

from __future__ import annotations

import socket as _socket
from typing import Dict

from .._ip import _required_family
from ._endpoint import UDPEndpoint

_PKTINFO_SUPPORT: "Dict[int, bool]" = {}


def has_pktinfo(family: int = _socket.AF_INET) -> bool:
    """Whether a UDP socket of *family* can report each datagram's arrival
    interface on this host.

    The question a server asks **before** deciding how to bind: with packet
    info, one wildcard socket serves every address and still knows which one a
    datagram reached; without it the wildcard has to be expanded into a socket
    per address, which on Linux then receives no broadcasts at all.

    ::

        if has_pktinfo():
            socks = [bind("", 67)]
        else:
            socks = [bind(str(a), 67) for a in addresses]

    **Decided by asking a socket, not by testing a name**, which is the only
    reliable way: ``getattr(socket, "IP_PKTINFO", None)`` is ``None`` on CPython
    3.9-3.11 on *every* platform -- the constant arrived in 3.12 -- while the
    kernel supported it throughout. A name test therefore reports "no" on a
    platform that works, which silently pushes a server onto the per-address
    path it did not need. :class:`UDPEndpoint` already used the documented
    per-platform values rather than the constants for exactly this reason, and
    this asks it the same way the endpoint does, on a throwaway socket.

    The answer is **cached per family** for the life of the process, since it is
    a property of the platform and the interpreter rather than of any socket.

    *family* is ``4`` or ``AF_INET``, ``6`` or ``AF_INET6``; anything else raises
    :class:`ValueError`, since a silent ``False`` for a misspelt family is a
    wrong answer.

    Returns ``False`` rather than raising if a socket of that family cannot even
    be created -- a v6 answer on a host with IPv6 disabled is "no", not an
    error.
    """
    family = _required_family(family)
    cached = _PKTINFO_SUPPORT.get(family)
    if cached is not None:
        return cached

    try:
        probe = _socket.socket(family, _socket.SOCK_DGRAM)
    except OSError:
        # No socket of this family at all, so nothing to report an arrival on.
        _PKTINFO_SUPPORT[family] = False
        return False
    try:
        answer = bool(UDPEndpoint(probe).has_pktinfo)
    finally:
        probe.close()
    _PKTINFO_SUPPORT[family] = answer
    return answer
