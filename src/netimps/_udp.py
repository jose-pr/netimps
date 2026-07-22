"""UDP receive with arrival-interface information (internal).

A server bound to the wildcard address cannot tell which interface a datagram
arrived on -- ``recvfrom`` reports the *sender*, not the local adapter. For
broadcast protocols (DHCP being the canonical case) that is exactly the thing
you need, because the reply depends on which network the request came from.

The answer is ``IP_PKTINFO``: a socket option that makes the kernel attach the
receiving interface index and local address as ancillary data, read back with
``recvmsg``.

Re-exported from :mod:`netimps`.

Platform reality
----------------
``IP_PKTINFO`` and ``socket.recvmsg`` are **not universally available** --
``recvmsg`` is absent on Windows entirely. Rather than failing, this degrades
to plain ``recvfrom`` and reports ``interface=None``, the same policy
:func:`netimps.get_pmtu` uses for the missing ``IP_MTU``. Check
:attr:`UdpEndpoint.supports_pktinfo` if you need to know which mode you are in.
"""

from __future__ import annotations

import socket as _socket
import struct as _struct
from typing import Any, NamedTuple, Optional

__all__ = ["UdpEndpoint", "Datagram"]

#: The option, where it exists. Probed rather than assumed.
_IP_PKTINFO = getattr(_socket, "IP_PKTINFO", None)
_CMSG_SPACE = getattr(_socket, "CMSG_SPACE", None)

#: ``struct in_pktinfo``: interface index, then the local and destination
#: addresses. Native byte order -- this never leaves the host.
_PKTINFO = "=I4s4s"


class Datagram(NamedTuple):
    """One received datagram and where it came from.

    Attributes:
        data: the payload.
        sender: ``(address, port)`` of the peer, as ``recvfrom`` reports it.
        local_address: the address the datagram was sent *to*, or ``None``.
            For a broadcast this is the broadcast address, not the interface's
            own address -- use ``interface`` to identify the adapter.
        interface_index: receiving interface index, or ``0`` when unknown.
        interface: the resolved :class:`Interface`, or ``None`` when
            unavailable (no ``IP_PKTINFO``, or no matching adapter).
    """

    data: bytes
    sender: Any
    local_address: Optional[Any] = None
    interface_index: int = 0
    interface: Optional[Any] = None


class UdpEndpoint:
    """A UDP socket that can report which interface each datagram arrived on.

    ::

        endpoint = UdpEndpoint(netimps.bind("", 67, broadcast=True))
        while True:
            packet = endpoint.recv(2048)
            if packet.interface is not None:
                reply_on(packet.interface, packet.data)

    Wraps rather than subclasses ``socket.socket``: the raw socket stays
    reachable as :attr:`socket` for anything this does not cover.

    :param sock: an already-bound UDP socket -- build it with
        :func:`netimps.bind`.
    :param pktinfo: request arrival-interface data. ``True`` (the default)
        enables it where supported and is a no-op elsewhere.
    """

    __slots__ = ("socket", "supports_pktinfo", "_cmsg_size")

    def __init__(self, sock, pktinfo: bool = True) -> None:
        self.socket = sock
        self.supports_pktinfo = False
        self._cmsg_size = 0

        if not pktinfo or _IP_PKTINFO is None or _CMSG_SPACE is None:
            return
        if not hasattr(sock, "recvmsg"):
            return  # Windows
        try:
            sock.setsockopt(_socket.IPPROTO_IP, _IP_PKTINFO, 1)
        except OSError:
            return  # option exists but this socket/family refuses it
        self.supports_pktinfo = True
        self._cmsg_size = _CMSG_SPACE(_struct.calcsize(_PKTINFO))

    def recv(self, bufsize: int = 65535, resolve_interface: bool = True) -> Datagram:
        """Receive one datagram.

        :param resolve_interface: look the arrival index up in
            :func:`netimps.get_interfaces` to populate ``.interface``. Pass
            ``False`` in a hot loop and use ``.interface_index`` directly --
            enumeration is not free.

        When ``IP_PKTINFO`` is unavailable this still works; the interface
        fields are simply empty.
        """
        if not self.supports_pktinfo:
            data, sender = self.socket.recvfrom(bufsize)
            return Datagram(data=data, sender=sender)

        data, ancdata, _flags, sender = self.socket.recvmsg(bufsize, self._cmsg_size)

        index = 0
        local = None
        size = _struct.calcsize(_PKTINFO)
        for level, ctype, cdata in ancdata:
            if level != _socket.IPPROTO_IP or ctype != _IP_PKTINFO:
                continue
            if len(cdata) < size:
                break  # truncated -- treat as absent rather than guessing
            index, _local_if, destination = _struct.unpack(_PKTINFO, cdata[:size])
            from . import try_parse

            local = try_parse(_socket.inet_ntoa(destination))
            break

        interface = None
        if resolve_interface and index:
            from ._ifaddrs import get_interfaces

            interface = next((i for i in get_interfaces() if i.index == index), None)

        return Datagram(
            data=data,
            sender=sender,
            local_address=local,
            interface_index=int(index),
            interface=interface,
        )

    def send(self, data, address, port: int, src=None) -> int:
        """Send a datagram, optionally forcing the *src* interface.

        ``src`` accepts the usual union (an :class:`Interface`, a MAC, an
        adapter name or an address). Where ``IP_PKTINFO`` is available this
        pins the outgoing interface via ``sendmsg`` -- which matters when
        replying to a broadcast on a multi-homed host, since the routing table
        would otherwise pick for you.

        Falls back to plain ``sendto`` when unsupported, so the call works
        everywhere; the src is then whatever the kernel chooses.
        """
        target = (str(address), int(port))

        if src is None or not self.supports_pktinfo:
            return self.socket.sendto(data, target)

        from ._iface_spec import interface_address

        local = interface_address(src, strict=False)
        if local is None or not hasattr(self.socket, "sendmsg"):
            return self.socket.sendto(data, target)

        packed = _socket.inet_aton(str(local))
        pktinfo = _struct.pack(_PKTINFO, 0, packed, packed)
        return int(
            self.socket.sendmsg(
                [data], [(_socket.IPPROTO_IP, _IP_PKTINFO, pktinfo)], 0, target
            )
        )

    def close(self) -> None:
        self.socket.close()

    def __enter__(self) -> "UdpEndpoint":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __repr__(self) -> str:
        try:
            bound = self.socket.getsockname()
        except OSError:  # unbound, or closed
            bound = None
        return "UdpEndpoint(bound=%r, pktinfo=%r)" % (bound, self.supports_pktinfo)
