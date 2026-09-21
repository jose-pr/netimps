"""UDP receive with arrival-interface information (internal).

A server bound to the wildcard address cannot tell which interface a datagram
arrived on -- ``recvfrom`` reports the *sender*, not the local adapter. For
broadcast protocols (DHCP being the canonical case) that is exactly the thing
you need, because the reply depends on which network the request came from.

The answer is the ``PKTINFO`` family of socket options: the kernel attaches the
receiving interface index and local address as ancillary data, read back with
``recvmsg``.

Re-exported from :mod:`netimps`.

One option per address family
-----------------------------
``IP_PKTINFO`` is the **IPv4** option and is not a spelling of the v6 one.
Setting it on an ``AF_INET6`` socket *succeeds* on Linux -- so a guard that
only watches for ``OSError`` sees nothing wrong -- and then no cmsg ever
arrives, because an IPv6 datagram carries ``IPV6_PKTINFO`` instead. The family
therefore selects the option, the cmsg type **and** the struct layout, and all
three differ:

- ``AF_INET``: set ``IP_PKTINFO``, match ``IP_PKTINFO``, unpack ``=I4s4s``
  (``struct in_pktinfo``: interface index first, then the addresses).
- ``AF_INET6``: set ``IPV6_RECVPKTINFO`` (Linux 49), match ``IPV6_PKTINFO``
  (Linux 50), unpack ``=16sI`` (``struct in6_pktinfo``: the 16-byte **address
  first**, then the index).

Note the v6 asymmetry -- the option you *set* is not the cmsg type you
*match* -- and the reversed field order. Neither is a detail you can guess.

A dual-stack ``AF_INET6`` socket needs only its own option. Measured on Linux:
with ``IPV6_RECVPKTINFO`` alone, an IPv4-mapped arrival reports
``::ffff:127.0.0.1`` with the correct interface index, so enabling
``IP_PKTINFO`` as well would only add a second, redundant cmsg to every
packet. :meth:`UdpEndpoint.recv` still dispatches on the received
``cmsg_level``, so a caller who enables further options on the raw socket gets
handled rather than misread.

Platform reality
----------------
These options and ``socket.recvmsg`` are **not universally available** --
``recvmsg`` and ``sendmsg`` are absent on Windows entirely, whatever the
constants say. Rather than failing, this degrades to plain ``recvfrom``/
``sendto`` and reports ``interface=None``, the same policy
:func:`netimps.get_pmtu` uses for the missing ``IP_MTU``. Check
:attr:`UdpEndpoint.supports_pktinfo` (receiving) and
:attr:`UdpEndpoint.supports_src_pinning` (sending) to know which mode you are
in -- both are decided once, at construction, from the socket's own family.
"""

from __future__ import annotations

import socket as _socket
import struct as _struct
from typing import NamedTuple, Optional, Tuple, Union

from ._iface_spec import InterfaceSpec
from ._ifaddrs import Interface
from ._ip import AddressLike, IPAddress, IPv4Address, IPv6Address, _dst_argument

__all__ = ["UdpEndpoint", "Datagram"]

#: The options, where they exist. Probed rather than assumed -- and probed
#: separately per family, because a platform can have one and not the other:
#: Windows exports ``IP_PKTINFO`` and ``IPV6_PKTINFO`` as numbers, has no
#: ``IPV6_RECVPKTINFO`` at all, and supports neither ``recvmsg`` nor
#: ``sendmsg``, which is what actually decides the matter there.
_IP_PKTINFO = getattr(_socket, "IP_PKTINFO", None)
_IPV6_PKTINFO = getattr(_socket, "IPV6_PKTINFO", None)
_IPV6_RECVPKTINFO = getattr(_socket, "IPV6_RECVPKTINFO", None)
_CMSG_SPACE = getattr(_socket, "CMSG_SPACE", None)
_MSG_CTRUNC = getattr(_socket, "MSG_CTRUNC", 0)

#: ``struct in_pktinfo``: interface index, then the local and destination
#: addresses. Native byte order -- this never leaves the host.
_PKTINFO_V4 = "=I4s4s"

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

#: Ancillary-buffer sizing. Room for exactly one cmsg is the wrong answer: the
#: caller owns the raw socket and may have enabled ``SO_TIMESTAMP`` or
#: ``IPV6_RECVHOPLIMIT`` on it, and a one-cmsg buffer then drops whichever
#: arrives second. Measured on Linux with both ``SO_TIMESTAMP`` and
#: ``IP_PKTINFO`` enabled: a one-slot buffer kept the timestamp, discarded the
#: pktinfo and set ``MSG_CTRUNC``; a four-slot buffer delivered both. Four
#: 64-byte slots cost 320 bytes per receive, and ``MSG_CTRUNC`` is reported as
#: :attr:`Datagram.control_truncated` for the cases that still overflow.
_CMSG_SLOTS = 4
_CMSG_SLOT_BYTES = 64

#: What ``recvfrom``/``recvmsg`` report as the peer: ``(address, port)`` for
#: IPv4, ``(address, port, flowinfo, scope_id)`` for IPv6. Kept out of the
#: public surface -- like ``InterfaceSpec`` it documents an established shape
#: rather than something a caller constructs.
SocketAddress = Union[Tuple[str, int], Tuple[str, int, int, int]]


def _pktinfo_options(family: int) -> "Tuple[int, Optional[int], Optional[int], str]":
    """``(level, receive option, send cmsg type, struct layout)`` for *family*.

    The receive option and the send cmsg type are the *same* constant for
    IPv4 and two *different* ones for IPv6 (``IPV6_RECVPKTINFO`` requests the
    data, ``IPV6_PKTINFO`` carries it), so they are returned separately rather
    than collapsed into one "the option" value.

    Either may be ``None`` where the platform does not export it; the caller
    turns that into a ``supports_*`` flag rather than an error.
    """
    if family == _socket.AF_INET6:
        return _socket.IPPROTO_IPV6, _IPV6_RECVPKTINFO, _IPV6_PKTINFO, _PKTINFO_V6
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
    from . import try_parse

    if level == _socket.IPPROTO_IP and ctype in _V4_PKTINFO_TYPES:
        size = _struct.calcsize(_PKTINFO_V4)
        if len(cdata) < size:
            return None
        index, _local_if, destination = _struct.unpack(_PKTINFO_V4, cdata[:size])
        return int(index), try_parse(destination)

    if level == _socket.IPPROTO_IPV6 and ctype in _V6_PKTINFO_TYPES:
        size = _struct.calcsize(_PKTINFO_V6)
        if len(cdata) < size:
            return None
        destination, index = _struct.unpack(_PKTINFO_V6, cdata[:size])
        return int(index), try_parse(destination)

    return None


class Datagram(NamedTuple):
    """One received datagram and where it came from.

    Attributes:
        data: the payload.
        sender: ``(address, port)`` of the peer, as ``recvfrom`` reports it --
            a four-tuple for an IPv6 socket.
        local_address: the address the datagram was sent *to*, or ``None``.
            For a broadcast this is the broadcast address, not the interface's
            own address -- use ``interface`` to identify the adapter. On a
            dual-stack IPv6 socket an IPv4 arrival reports the v4-mapped form
            (``::ffff:10.0.0.1``), matching what ``sender`` shows.
        interface_index: receiving interface index, or ``0`` when unknown.
        interface: the resolved :class:`Interface`, or ``None`` when
            unavailable (no pktinfo, or no matching adapter).
        control_truncated: the kernel had more ancillary data than the buffer
            held (``MSG_CTRUNC``). When this is ``True`` and the interface
            fields are empty, they are empty because something was dropped --
            not because the kernel had nothing to say.
    """

    data: bytes
    sender: "SocketAddress"
    local_address: "Optional[IPAddress]" = None
    interface_index: int = 0
    interface: "Optional[Interface]" = None
    control_truncated: bool = False


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
        :func:`netimps.bind`. Its ``family`` decides which pktinfo option is
        used; an ``AF_INET6`` socket gets the v6 one, including when it is
        dual-stack.
    :param pktinfo: request arrival-interface data. ``True`` (the default)
        enables it where supported and is a no-op elsewhere. This governs
        *receiving* only -- :meth:`send`'s ``src`` needs no socket option.

    Two flags report what this socket can actually do, so a caller never has
    to infer it from an empty result:

    :ivar supports_pktinfo: ``recv`` will report the arrival interface. This
        is ``False`` -- not an optimistic ``True`` -- whenever the option for
        *this socket's family* is missing or refused.
    :ivar supports_src_pinning: :meth:`send` can honour ``src``. ``False``
        where the platform has no ``sendmsg`` (Windows) or no pktinfo cmsg for
        this family (macOS has no ``IP_PKTINFO``); ``src`` is then ignored,
        and the kernel picks the source as it always would.
    """

    __slots__ = ("socket", "supports_pktinfo", "supports_src_pinning", "_cmsg_size")

    def __init__(self, sock: "_socket.socket", pktinfo: bool = True) -> None:
        self.socket = sock
        self.supports_pktinfo = False
        self.supports_src_pinning = False
        self._cmsg_size = 0

        family = getattr(sock, "family", _socket.AF_INET)
        level, receive_option, send_type, _layout = _pktinfo_options(family)

        # Sending needs no socket option, only ``sendmsg`` and a cmsg type for
        # the family -- so it is decided independently of ``pktinfo=``, which
        # is about what arrives.
        self.supports_src_pinning = send_type is not None and hasattr(sock, "sendmsg")

        if not pktinfo or receive_option is None or _CMSG_SPACE is None:
            return
        if not hasattr(sock, "recvmsg"):
            return  # Windows
        try:
            sock.setsockopt(level, receive_option, 1)
        except OSError:
            return  # option exists but this socket/family refuses it
        self.supports_pktinfo = True
        self._cmsg_size = _CMSG_SPACE(_CMSG_SLOT_BYTES) * _CMSG_SLOTS

    def recv(self, bufsize: int = 65535, resolve_interface: bool = True) -> Datagram:
        """Receive one datagram.

        :param resolve_interface: look the arrival index up in
            :func:`netimps.get_interfaces` to populate ``.interface``. Pass
            ``False`` in a hot loop and use ``.interface_index`` directly --
            enumeration is not free.

        When pktinfo is unavailable this still works; the interface fields are
        simply empty. When it *is* available -- :attr:`supports_pktinfo` --
        the interface fields are filled for both address families, and
        ``.control_truncated`` says whether anything was dropped for want of
        buffer space.
        """
        if not self.supports_pktinfo:
            data, sender = self.socket.recvfrom(bufsize)
            return Datagram(data=data, sender=sender)

        # recvmsg is POSIX-only; the hasattr guard in __init__ is what makes
        # this unreachable on Windows, which the type stubs cannot express.
        data, ancdata, flags, sender = self.socket.recvmsg(  # type: ignore[attr-defined]
            bufsize, self._cmsg_size
        )

        index = 0
        local: "Optional[IPAddress]" = None
        for level, ctype, cdata in ancdata:
            decoded = _unpack_pktinfo(level, ctype, cdata)
            if decoded is None:
                continue
            index, local = decoded
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
            control_truncated=bool(flags & _MSG_CTRUNC),
        )

    def _pktinfo_control(
        self, src: "InterfaceSpec"
    ) -> "Optional[Tuple[int, int, bytes]]":
        """Build the ``(level, type, data)`` cmsg that pins *src*, or ``None``.

        ``None`` means the platform cannot pin at all (no ``sendmsg``), which
        is the documented degrade. A *spec* that names nothing local raises
        :class:`ValueError` instead of being dropped: the caller asked for a
        specific adapter, and sending from another one is the silent wrong
        answer this exists to prevent.

        Both halves of the struct are filled where they resolve. Index alone
        is "this adapter, kernel picks the address"; address alone is "this
        address, kernel picks the adapter" -- and the outgoing struct is the
        only place the interface can be named, which the previous
        hardcoded-zero index never did.
        """
        if not self.supports_src_pinning:
            return None

        from ._iface_spec import interface_address, interface_index

        family = self.socket.family
        level, _receive_option, send_type, _layout = _pktinfo_options(family)
        if send_type is None:  # pragma: no cover - guarded by the flag above
            return None
        want_ipv6 = family == _socket.AF_INET6

        # Both lookups are tolerant: a spec may name an adapter with no
        # address of the wanted family (index only), or an address no local
        # adapter claims (address only). Only resolving to *neither* is an
        # error. Passing an Interface answers both without enumerating.
        local = interface_address(src, want_ipv6=want_ipv6, strict=False)
        index = interface_index(src, strict=False) or 0
        if local is None and not index:
            raise ValueError(
                "cannot resolve src %r to a local address or interface index" % (src,)
            )

        if want_ipv6:
            if isinstance(local, IPv4Address):
                # A dual-stack socket sends IPv4 as v4-mapped, and so must the
                # source it is pinned to. Measured on Linux: pinning
                # ::ffff:127.0.0.1 delivers, and the receiver sees 127.0.0.1.
                local = IPv6Address("::ffff:%s" % (local,))
            packed = local.packed if local is not None else b"\x00" * 16
            return level, send_type, _struct.pack(_PKTINFO_V6, packed, index)

        if isinstance(local, IPv6Address):
            raise ValueError(
                "cannot pin an IPv6 source (%s) on an AF_INET socket -- "
                "build the endpoint on an AF_INET6 socket instead" % (local,)
            )
        packed = local.packed if local is not None else b"\x00" * 4
        # ipi_addr is the *destination* on receipt and ignored on send; only
        # ipi_spec_dst selects the source address. Measured: zeroing it
        # changes nothing, and filling it with the source was misleading.
        return level, send_type, _struct.pack(_PKTINFO_V4, index, packed, b"\x00" * 4)

    def send(
        self,
        data: bytes,
        address: "AddressLike",
        port: int,
        src: "InterfaceSpec" = None,
    ) -> int:
        """Send a datagram, optionally forcing the *src* interface.

        ``src`` accepts the usual union (an :class:`Interface`, a MAC, an
        adapter name or an address). Where the platform has ``sendmsg`` this
        pins the outgoing interface *and* source address via the family's
        pktinfo cmsg -- which matters when replying to a broadcast on a
        multi-homed host, since the routing table would otherwise pick for
        you.

        The cmsg follows the socket's family: ``in6_pktinfo`` for
        ``AF_INET6`` (a v4 source is converted to its v4-mapped form),
        ``in_pktinfo`` for ``AF_INET``. Sending an IPv6 cmsg on an ``AF_INET``
        socket is *accepted and ignored* by Linux, so an IPv6 ``src`` there
        raises :class:`ValueError` rather than reporting a success that did
        not happen.

        Where ``sendmsg`` does not exist -- Windows -- ``src`` cannot be
        honoured at all: the datagram goes out unpinned, from whichever
        address the kernel chooses, and the spec is not even resolved. That is
        the module's usual degrade, and :attr:`supports_src_pinning` is
        ``False`` there, so a caller who cares can check once rather than
        inferring it from a silent success.

        Raises :class:`ValueError` for a ``src`` that names no local address
        or interface, and lets an :class:`OSError` from the kernel through --
        a source address this host cannot send from is a real failure, not an
        unsupported platform.

        Resolving a MAC, adapter name or bare address enumerates interfaces;
        pass an :class:`Interface` in a send loop to avoid that.
        """
        target = (_dst_argument(address), int(port))

        if src is None:
            return self.socket.sendto(data, target)

        control = self._pktinfo_control(src)
        if control is None:
            return self.socket.sendto(data, target)

        # sendmsg is POSIX-only, same as recvmsg above.
        return int(
            self.socket.sendmsg(  # type: ignore[attr-defined]
                [data], [control], 0, target
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
        return "UdpEndpoint(bound=%r, pktinfo=%r, src_pinning=%r)" % (
            bound,
            self.supports_pktinfo,
            self.supports_src_pinning,
        )
