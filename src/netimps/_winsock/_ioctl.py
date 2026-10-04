"""``SIO_UDP_CONNRESET``: the switch CPython's ``socket.ioctl`` refuses."""

from __future__ import annotations

import ctypes as _ctypes
from typing import Any

from ._abi import _DWORD, _raise_last_error, _ws2

#: ``SIO_UDP_CONNRESET`` = ``_WSAIOW(IOC_VENDOR, 12)`` =
#: ``IOC_IN | IOC_VENDOR | 12``. Computed here rather than imported because
#: **CPython exports no such constant on any version**, and even given the right
#: number ``socket.ioctl`` refuses it: that method whitelists a handful of
#: commands (``SIO_RCVALL``, ``SIO_KEEPALIVE_VALS``, ``SIO_LOOPBACK_FAST_PATH``)
#: and raises ``ValueError: invalid ioctl command`` for anything else. So there is
#: no stdlib route to this behaviour at all, and ``WSAIoctl`` is the only way.
_IOC_IN = 0x80000000
_IOC_VENDOR = 0x18000000
SIO_UDP_CONNRESET = _IOC_IN | _IOC_VENDOR | 12


def set_udp_connreset(sock: "Any", enabled: bool) -> None:
    """Turn ``SIO_UDP_CONNRESET`` on or off for *sock*.

    With it off, Windows stops reporting an ICMP port-unreachable provoked by an
    earlier send as ``ConnectionResetError`` on a later, unrelated receive.

    Raises ``OSError`` if Winsock refuses -- the caller decides whether that
    matters, since this is an adjustment to behaviour rather than a correctness
    requirement.
    """
    value = _ctypes.c_ulong(1 if enabled else 0)
    returned = _DWORD()
    rc = _ws2.WSAIoctl(
        sock.fileno(),
        SIO_UDP_CONNRESET,
        _ctypes.byref(value),
        _ctypes.sizeof(value),
        None,
        0,
        _ctypes.byref(returned),
        None,
        None,
    )
    if rc != 0:
        _raise_last_error()
