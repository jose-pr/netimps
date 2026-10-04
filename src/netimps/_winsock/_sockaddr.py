"""Converting between ``sockaddr`` buffers and CPython's address tuples."""

from __future__ import annotations

import ctypes as _ctypes
import socket as _socket
from typing import Any, Optional

from ._abi import _SOCKADDR_IN, _SOCKADDR_IN6


def _decode_sockaddr(raw: bytes, family: int) -> "Optional[Any]":
    """Decode a raw ``sockaddr`` into the tuple ``recvfrom`` would return.

    ``AF_INET`` gives ``(host, port)``; ``AF_INET6`` gives
    ``(host, port, flowinfo, scope_id)`` -- a 4-tuple, matching CPython, so an
    IPv6 caller does not have to special-case which implementation answered.
    The port is network-order in the struct and host-order in the tuple, and
    ``flowinfo`` is masked to its 20 significant bits exactly as CPython's
    ``makesockaddr`` does.
    """
    if family == _socket.AF_INET6:
        if len(raw) < _ctypes.sizeof(_SOCKADDR_IN6):
            return None
        sa6 = _SOCKADDR_IN6.from_buffer_copy(raw[: _ctypes.sizeof(_SOCKADDR_IN6)])
        host = _socket.inet_ntop(_socket.AF_INET6, bytes(sa6.sin6_addr))
        return (
            host,
            _socket.ntohs(sa6.sin6_port),
            _socket.ntohl(sa6.sin6_flowinfo) & 0xFFFFF,
            sa6.sin6_scope_id,
        )
    if family == _socket.AF_INET:
        if len(raw) < _ctypes.sizeof(_SOCKADDR_IN):
            return None
        sa4 = _SOCKADDR_IN.from_buffer_copy(raw[: _ctypes.sizeof(_SOCKADDR_IN)])
        host = _socket.inet_ntop(_socket.AF_INET, bytes(sa4.sin_addr))
        return (host, _socket.ntohs(sa4.sin_port))
    return None


def _encode_sockaddr(address: "Any", family: int) -> "Any":
    """Build a ``sockaddr`` buffer from a CPython-style address tuple.

    Accepts the 2-tuple for ``AF_INET`` and the 2-, 3- or 4-tuple for
    ``AF_INET6``, since ``sendto`` is equally lenient about the trailing
    ``flowinfo``/``scope_id``.
    """
    if not isinstance(address, (tuple, list)) or len(address) < 2:
        raise TypeError("address must be a (host, port[, flowinfo, scope_id]) tuple")
    host = address[0]
    port = int(address[1])
    if family == _socket.AF_INET6:
        flowinfo = int(address[2]) if len(address) > 2 else 0
        scope_id = int(address[3]) if len(address) > 3 else 0
        if "%" in host:
            # A scope suffix in the host wins over a missing scope_id, so
            # "fe80::1%12" works the way it does for getaddrinfo callers.
            host, _, zone = host.partition("%")
            if not scope_id:
                scope_id = int(zone) if zone.isdigit() else _if_nametoindex(zone)
        sa6 = _SOCKADDR_IN6(
            sin6_family=_socket.AF_INET6,
            sin6_port=_socket.htons(port),
            sin6_flowinfo=_socket.htonl(flowinfo),
            sin6_scope_id=scope_id,
        )
        packed = _packed_host(host, _socket.AF_INET6)
        _ctypes.memmove(sa6.sin6_addr, packed, 16)
        return sa6
    sa4 = _SOCKADDR_IN(
        sin_family=_socket.AF_INET,
        sin_port=_socket.htons(port),
    )
    packed = _packed_host(host, _socket.AF_INET)
    _ctypes.memmove(sa4.sin_addr, packed, 4)
    return sa4


def _packed_host(host: str, family: int) -> bytes:
    """The packed address of *host* for *family*: a literal, else a looked-up name.

    CPython's ``sendmsg`` accepts a host name and the empty string (the
    wildcard) as ``sendto`` does, so this does too.
    """
    try:
        return _socket.inet_pton(family, host)
    except OSError:
        pass
    if host == "":
        return b"\x00" * (16 if family == _socket.AF_INET6 else 4)
    if host == "<broadcast>" and family == _socket.AF_INET:
        return b"\xff" * 4
    resolved = _socket.getaddrinfo(host, None, family, _socket.SOCK_DGRAM)[0][4][0]
    return _socket.inet_pton(family, str(resolved).partition("%")[0])


def _if_nametoindex(zone: str) -> int:
    try:
        return _socket.if_nametoindex(zone)
    except (AttributeError, OSError):
        return 0
