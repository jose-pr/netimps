"""Sending a datagram with its source pinned by a pktinfo cmsg (internal)."""

from __future__ import annotations

import socket as _socket
import struct as _struct
from typing import Optional, Tuple

from .._iface_spec import InterfaceLike
from .._ip import (
    HostLike,
    IPAddress,
    IPv4Address,
    IPv6Address,
    _dst_argument,
)
from .._msg import sendmsg as _sendmsg
from .._parse import try_parse
from .._pktinfo import (
    _IS_WINDOWS,
    _PKTINFO_V4,
    _PKTINFO_V4_ADDR_FIRST,
    _PKTINFO_V6,
    _pktinfo_options,
)
from . import _freebsd
from ._timeout import _builtin_timeout


def _refuse_zero_source(local: "Optional[IPAddress]", index: int) -> None:
    """Raise on Windows for a pin that would send from the zero address.

    Windows sends a zero source address **literally**: measured, a pin of
    ``0.0.0.0`` or ``::`` arrives from that address rather than letting the
    kernel choose, which is what Linux does with the same bytes. An index-only
    pin, or a literal zero, cannot be expressed this way there, and silently
    sending from the zero address would be far worse than refusing.
    """
    if local is None:
        raise ValueError(
            "cannot pin by interface index alone on Windows (index %d): the "
            "platform sends a zero source address literally rather than "
            "choosing one. Pass an address-bearing src instead." % (index,)
        )
    if local.is_unspecified:
        raise ValueError(
            "cannot pin the unspecified address %s on Windows: the platform "
            "sends a zero source address literally rather than choosing one. "
            "Pass an address-bearing src instead." % (local,)
        )


def _zone_index(address: "IPAddress") -> int:
    """The interface index an IPv6 ``%zone`` names, else ``0`` (kernel's choice)."""
    zone = getattr(address, "scope_id", None)
    if not zone:
        return 0
    if str(zone).isdigit():
        return int(zone)
    try:
        return _socket.if_nametoindex(str(zone))
    except (OSError, AttributeError, ValueError):
        return 0


class _SendMixin:
    """``send`` and the cmsg it pins the source with, for :class:`UDPEndpoint`."""

    __slots__ = ()

    socket: "_socket.socket"
    has_src_pinning: bool

    def _pktinfo_control(
        self, src: "InterfaceLike"
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
        only place the interface can be named; an index fixed at zero never
        names one.
        """
        if not self.has_src_pinning:
            return None

        from .._iface_spec import interface_address, interface_index

        family = self.socket.family
        level, _receive_option, send_type, _layout = _pktinfo_options(family)
        want_ipv6 = family == _socket.AF_INET6
        by_address_only = _freebsd.IS_FREEBSD and not want_ipv6
        if send_type is None and not by_address_only:  # pragma: no cover
            return None  # guarded by the flag above

        local: "Optional[IPAddress]"
        literal = src if isinstance(src, (IPv4Address, IPv6Address)) else None
        if literal is None and isinstance(src, str):
            literal = try_parse(src, IPAddress)
        if literal is not None:
            # An address is already what the cmsg carries, so it is used as
            # given. Resolving it to its adapter means enumerating every
            # interface on each send -- measured at 1.29 ms against 0.04 ms for
            # an `Interface`. The cost is that the kernel, not this call, picks
            # the adapter; a `%zone` still names one.
            local = literal
            index = _zone_index(literal)
        else:
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

        if by_address_only:
            # IPv4 on FreeBSD has no index pin: an interface is pinned by its
            # IPv4 address, which `interface_address` took from it above.
            if isinstance(local, IPv6Address):
                raise ValueError(
                    "cannot pin an IPv6 source (%s) on an AF_INET socket -- "
                    "build the endpoint on an AF_INET6 socket instead" % (local,)
                )
            if local is None:
                raise ValueError(
                    "cannot pin src %r on FreeBSD: IPv4 is pinned by address "
                    "and it names no IPv4 address" % (src,)
                )
            if local.is_unspecified:
                # The kernel refuses a zero source (errno 22) where Linux and
                # macOS read it as "kernel chooses". No message asks the same.
                return None
            return _freebsd.source_control(local)

        if send_type is None:  # pragma: no cover - the by-address case returned
            return None

        if want_ipv6:
            if _IS_WINDOWS:
                from .._ip import unmap

                if local is not None:
                    local = unmap(local)
                _refuse_zero_source(local, index)
                if isinstance(local, IPv4Address):
                    # A dual-stack socket takes an IPv4 source as an IPPROTO_IP
                    # IN_PKTINFO, the message recv decodes for an IPv4 arrival;
                    # the IPv6 one is refused with WSAEINVAL for a mapped
                    # address (WinError 10022).
                    ip_level, _opt, ip_type, _ip_layout = _pktinfo_options(
                        _socket.AF_INET
                    )
                    assert ip_type is not None
                    return (
                        ip_level,
                        ip_type,
                        _struct.pack(_PKTINFO_V4, local.packed, index),
                    )
            elif isinstance(local, IPv4Address):
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
        if _IS_WINDOWS:
            _refuse_zero_source(local, index)
        packed = local.packed if local is not None else b"\x00" * 4
        if _PKTINFO_V4_ADDR_FIRST:
            # Windows IN_PKTINFO has no spec_dst, and ipi_addr *is* the field
            # the send path reads -- the opposite of POSIX below.
            return level, send_type, _struct.pack(_PKTINFO_V4, packed, index)
        # ipi_addr is the *destination* on receipt and ignored on send; only
        # ipi_spec_dst selects the source address. Measured: zeroing it
        # changes nothing, and filling it with the source was misleading.
        return level, send_type, _struct.pack(_PKTINFO_V4, index, packed, b"\x00" * 4)

    @_builtin_timeout
    def send(
        self,
        data: bytes,
        dst: "HostLike",
        port: int,
        *,
        src: "InterfaceLike" = None,
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

        **Windows is supported**, via ``WSASendMsg``. The one gap there is
        pinning by interface *index alone*, which raises
        :class:`ValueError` rather than degrading, because Windows sends a zero
        source address literally where POSIX reads it as "kernel chooses".

        Where a platform genuinely cannot pin -- no pktinfo cmsg for the family
        -- the datagram goes out unpinned and the spec is not resolved. That is
        the module's usual degrade, and :attr:`has_src_pinning` is ``False``
        there, so a caller who cares can check once rather than inferring it
        from a silent success.

        Raises :class:`ValueError` for a ``src`` that names no local address
        or interface, and lets an :class:`OSError` from the kernel through --
        a source address this host cannot send from is a real failure, not an
        unsupported platform.

        A ``src`` that is an **address** is used as given and enumerates nothing;
        the kernel then chooses the adapter, except that a ``%zone`` names one.
        Resolving a MAC or an adapter name enumerates interfaces; pass an
        :class:`Interface` in a send loop to avoid that, and to pin the adapter
        as well as the address.

        A timeout set on the socket raises the builtin :class:`TimeoutError`
        on every supported Python.
        """
        target = (_dst_argument(dst), int(port))

        if src is None:
            return self.socket.sendto(data, target)

        control = self._pktinfo_control(src)
        if control is None:
            return self.socket.sendto(data, target)

        # Through `_msg`, same reasoning as `recv` above.
        return int(_sendmsg(self.socket, [data], [control], 0, target))
