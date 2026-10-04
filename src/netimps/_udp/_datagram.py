"""The received-datagram value type (internal)."""

from __future__ import annotations

from typing import NamedTuple, Optional, Tuple, Union

from .._ifaddrs import Interface, is_unicast
from .._ip import IPAddress
from .._parse import try_parse

#: What ``recvfrom``/``recvmsg`` report as the peer: ``(address, port)`` for
#: IPv4, ``(address, port, flowinfo, scope_id)`` for IPv6. Kept out of the
#: public surface -- like ``InterfaceLike`` it documents an established shape
#: rather than something a caller constructs.
SocketAddress = Union[Tuple[str, int], Tuple[str, int, int, int]]


class Datagram(NamedTuple):
    """One received datagram and where it came from.

    Attributes:
        data: the payload.
        sender: ``(address, port)`` of the peer, as ``recvfrom`` reports it --
            a four-tuple for an IPv6 socket.
        destination: the address the datagram was sent *to*, or ``None``.
            For a broadcast this is the broadcast address, not the interface's
            own address -- use ``interface`` to identify the adapter. On a
            dual-stack IPv6 socket an IPv4 arrival reports the v4-mapped form
            (``::ffff:10.0.0.1``), matching what ``sender`` shows. Absent
            without pktinfo.
        interface_index: receiving interface index, or ``0`` when unknown.
        interface: the resolved :class:`Interface`, or ``None`` when
            unavailable (no pktinfo, or no matching adapter).
        control_truncated: the kernel had more ancillary data than the buffer
            held (``MSG_CTRUNC``). When this is ``True`` and the interface
            fields are empty, they are empty because something was dropped --
            not because the kernel had nothing to say.
        truncated: the **payload** did not fit ``bufsize`` and ``data`` is the
            leading part of a longer datagram (``MSG_TRUNC``). A different
            question from ``control_truncated``, and the one that silently
            corrupts a decode: a protocol parser handed a message cut
            mid-field reports a malformed packet rather than a short read.
            Measured on Linux with ``bufsize=576``: a 1102-octet datagram
            arrived with ``MSG_TRUNC`` set and the flag discarded, leaving the
            caller nothing to check. Reported, not raised -- deciding that a
            short datagram is fatal belongs to the protocol, not here.
    """

    data: bytes
    sender: "SocketAddress"
    destination: "Optional[IPAddress]" = None
    interface_index: int = 0
    interface: "Optional[Interface]" = None
    control_truncated: bool = False
    truncated: bool = False

    @property
    def is_unicast(self) -> "Optional[bool]":
        """Whether the datagram was addressed to one host: not a broadcast, a
        multicast group or the wildcard.

        ``None`` when ``destination`` is unknown -- there was no pktinfo -- since
        a guess in either direction would make a server answer, or ignore, the
        wrong packets. The subnet broadcast is judged against the arrival
        ``interface``, so this costs no enumeration when that is set; see
        :func:`netimps.is_unicast`.
        """
        if self.destination is None:
            return None
        return is_unicast(self.destination, self.interface, cache=True)

    @property
    def reply_address(self) -> "SocketAddress":
        """``sender``, in the family a :meth:`UDPEndpoint.reply_socket` will use.

        **Use this, not ``sender``, to answer a datagram.** On a dual-stack
        ``AF_INET6`` listener a v4 client's ``sender`` is the v6 4-tuple
        ``('::ffff:127.0.0.1', port, 0, 0)``, while ``reply_socket`` correctly
        hands back an ``AF_INET`` socket -- so ``reply.sendto(answer,
        packet.sender)`` raises ``TypeError: AF_INET address must be a pair
        (host, port)``. ``reply_address`` is the sender already in the family
        the library chose, so the caller does not unmap it::

            with endpoint.reply_socket(packet) as reply:
                reply.sendto(answer, packet.reply_address)

        A v4-mapped sender becomes the plain ``(host, port)`` pair; everything
        else is returned unchanged, so this is the right thing to pass on a
        single-family listener too.
        """
        from .._ip import unmap

        sender = self.sender
        if not isinstance(sender, tuple) or len(sender) < 2:
            return sender
        host = sender[0]
        if not isinstance(host, str):
            return sender
        parsed = try_parse(host.split("%")[0], IPAddress)
        if parsed is None or parsed.version != 6:
            return sender
        plain = unmap(parsed)
        if plain.version != 4:
            return sender
        # Drop flowinfo and scope id along with the mapping: they are v6
        # sockaddr fields and an AF_INET sendto rejects a 4-tuple outright.
        return (str(plain), sender[1])
