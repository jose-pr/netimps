"""The last-resort enumeration, through the host name."""

from __future__ import annotations

import socket as _socket
from typing import List, Optional
from ._model import Interface, _IPInterface, _make_ip_interface


def _fallback_interfaces(
    want_raw: bool, reason: "Optional[BaseException]" = None
) -> "List[Interface]":
    """Last-resort enumeration via ``getaddrinfo(gethostname())``.

    **Prefixes here are fiction.** There is no portable stdlib way to learn an
    address's real prefix, so every address is reported as a host route (``/32``
    or ``/128``) under a single synthetic interface. Reached only when the
    native call is unavailable or fails; check ``iface.name == "<unknown>"`` to
    detect it.
    """
    ips: "List[_IPInterface]" = []
    seen = set()
    hostname = _socket.gethostname()
    try:
        infos = _socket.getaddrinfo(hostname, None)
    except OSError:
        infos = []
    for family, _, _, _, sockaddr in infos:
        # getaddrinfo's sockaddr is typed as a union; the first element is the
        # address text for both AF_INET and AF_INET6.
        addr = str(sockaddr[0])
        if addr in seen:
            continue
        seen.add(addr)
        if family == _socket.AF_INET:
            built = _make_ip_interface(addr, 32)
        elif family == _socket.AF_INET6:
            built = _make_ip_interface(addr.split("%")[0], 128)
        else:
            continue
        if built is not None:
            ips.append(built)

    return [
        Interface(
            name="<unknown>",
            index=0,
            mac=None,
            ips=ips,
            raw=(
                {
                    "degraded": True,
                    "reason": (
                        "native enumeration unavailable"
                        if reason is None
                        else str(reason) or type(reason).__name__
                    ),
                }
                if want_raw
                else None
            ),
        )
    ]
