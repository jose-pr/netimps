"""Multicast group membership (internal).

Joining a multicast group is four setsockopt calls that are easy to get subtly
wrong, and the mistakes are silent: the socket binds, receives nothing, and
looks fine. This wraps the sequence with the defaults that make it work.

Re-exported from :mod:`netimps`.

The parts people get wrong
-------------------------
* **Binding to the group address vs ``""``.** Binding to the group works on
  Linux but fails on Windows; binding to ``""`` works everywhere. That is the
  default here.
* **Choosing the interface.** With no ``interface``, the kernel picks by
  routing table -- which on a host with VMs, containers or a VPN is regularly
  the wrong adapter, and the socket then receives nothing at all. Pass one when
  it matters.
* **``SO_REUSEPORT`` does not exist on Windows.** Code that sets it
  unconditionally raises there, so it is applied only where present.
* **Default TTL is 1**, confining traffic to the local link. Raising it is a
  deliberate act, not a detail to leave at whatever the OS chose.
"""

from __future__ import annotations

import socket as _socket
import struct as _struct
from typing import List, Optional, Union

__all__ = ["multicast_socket", "join_group", "leave_group", "is_multicast"]


def is_multicast(address) -> bool:
    """True if ``address`` is a multicast group (``224.0.0.0/4`` or ``ff00::/8``).

    ::

        is_multicast("224.0.0.251")   # True  -- mDNS
        is_multicast("ff02::fb")      # True
        is_multicast("10.0.0.1")      # False

    Never raises: anything unparseable is ``False``.
    """
    from . import IPAddress, try_parse

    parsed = try_parse(address, IPAddress)
    return bool(parsed is not None and parsed.is_multicast)


def _interface_address(interface, want_ipv6: bool) -> "Optional[str]":
    """Reduce an Interface/MAC/address/name to a usable local address.

    Multicast membership needs an *address* (IPv4) or an interface *index*
    (IPv6); an adapter name alone is not enough on either. Resolving here keeps
    the caller from having to know that.
    """
    from . import MACAddress, is_valid
    from ._ifaddrs import Interface, get_interfaces

    if interface is None:
        return None

    if isinstance(interface, MACAddress) or (
        isinstance(interface, str) and is_valid(interface, MACAddress)
    ):
        wanted = MACAddress(interface)
        interface = next(
            (iface for iface in get_interfaces() if iface.mac == wanted), None
        )
        if interface is None:
            raise ValueError("no interface with MAC %s" % (wanted,))

    from . import IPAddress

    if isinstance(interface, str) and not is_valid(interface, IPAddress):
        # Not an address literal, so treat it as an adapter name and look it
        # up -- failing here beats a confusing setsockopt error later.
        match = next(
            (iface for iface in get_interfaces() if iface.name == interface), None
        )
        if match is None:
            raise ValueError("no interface named %r" % (interface,))
        interface = match

    if isinstance(interface, Interface):
        candidates = interface.ipv6 if want_ipv6 else interface.ipv4
        for entry in candidates:
            if not entry.ip.is_loopback:
                return str(entry.ip)
        if candidates:
            return str(candidates[0].ip)
        raise ValueError(
            "interface %r has no %s address to join from"
            % (interface.name, "IPv6" if want_ipv6 else "IPv4")
        )

    return str(interface)


def _membership_request(group: str, interface_address: "Optional[str]", ipv6: bool):
    """Build the mreq structure for IP_ADD_MEMBERSHIP / IPV6_JOIN_GROUP."""
    if ipv6:
        index = 0
        if interface_address:
            try:
                index = _socket.if_nametoindex(interface_address)
            except (OSError, AttributeError, ValueError):
                index = 0
        return _socket.inet_pton(_socket.AF_INET6, group) + _struct.pack("@I", index)

    local = interface_address or "0.0.0.0"
    return _struct.pack("4s4s", _socket.inet_aton(group), _socket.inet_aton(local))


def join_group(sock, group: str, interface=None) -> None:
    """Join ``group`` on ``sock``, optionally via a specific ``interface``.

    ``interface`` accepts an :class:`Interface`, a MAC, an adapter name or a
    local address. Without one the kernel chooses by routing table, which on a
    host with VMs or a VPN is often the wrong adapter -- and the failure is
    silent: the socket simply never receives.

    Raises :class:`ValueError` for a non-multicast group or an interface with no
    usable address, and :class:`OSError` if the kernel rejects the join.
    """
    if not is_multicast(group):
        raise ValueError("%r is not a multicast group" % (group,))

    ipv6 = ":" in group
    address = _interface_address(interface, want_ipv6=ipv6)
    request = _membership_request(group, address, ipv6)
    if ipv6:
        sock.setsockopt(_socket.IPPROTO_IPV6, _socket.IPV6_JOIN_GROUP, request)
    else:
        sock.setsockopt(_socket.IPPROTO_IP, _socket.IP_ADD_MEMBERSHIP, request)


def leave_group(sock, group: str, interface=None) -> None:
    """Leave ``group`` on ``sock``. The inverse of :func:`join_group`.

    Closing the socket drops membership too, so this is only needed to leave a
    group while keeping the socket open.
    """
    if not is_multicast(group):
        raise ValueError("%r is not a multicast group" % (group,))

    ipv6 = ":" in group
    address = _interface_address(interface, want_ipv6=ipv6)
    request = _membership_request(group, address, ipv6)
    if ipv6:
        sock.setsockopt(_socket.IPPROTO_IPV6, _socket.IPV6_LEAVE_GROUP, request)
    else:
        sock.setsockopt(_socket.IPPROTO_IP, _socket.IP_DROP_MEMBERSHIP, request)


def multicast_socket(
    group: "Union[str, List[str], None]" = None,
    port: int = 0,
    interface=None,
    ttl: int = 1,
    loop: bool = True,
    bind: bool = True,
    reuse: bool = True,
):
    """Return a UDP socket configured for multicast, joined to ``group``.

    The whole setup in one call::

        sock = multicast_socket("224.0.0.251", 5353)     # mDNS listener
        data, sender = sock.recvfrom(2048)

        sender = multicast_socket(ttl=32, bind=False)    # send-only, off-link
        sender.sendto(b"hello", ("239.1.2.3", 9999))

    :param group: group to join, or a list of them. ``None`` configures the
        socket for sending without joining anything.
    :param port: local port to bind. ``0`` picks a free one; a listener must
        pass the port the senders use.
    :param interface: :class:`Interface`, MAC, adapter name or local address to
        join through. **Strongly recommended on multi-homed hosts** -- the
        routing-table default is frequently the wrong adapter.
    :param ttl: hop limit for outgoing datagrams. The default of **1 keeps
        traffic on the local link**; raise it deliberately to cross routers.
    :param loop: whether this host receives its own transmissions. ``True``
        (the default) is what you want when sender and listener share a host.
    :param bind: bind to ``port``. Binding to ``""`` rather than the group
        address, because binding to the group fails on Windows.
    :param reuse: set ``SO_REUSEADDR`` (plus ``SO_REUSEPORT`` where it exists),
        so several listeners can share the port. ``SO_REUSEPORT`` is absent on
        Windows and is skipped there rather than raising.

    The caller owns the socket and should close it; closing drops membership.
    Raises :class:`ValueError` for a non-multicast group, :class:`OSError` if
    binding or joining fails.
    """
    groups = [group] if isinstance(group, str) else list(group or [])
    ipv6 = any(":" in entry for entry in groups)
    family = _socket.AF_INET6 if ipv6 else _socket.AF_INET

    sock = _socket.socket(family, _socket.SOCK_DGRAM)
    try:
        if reuse:
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
            # Absent on Windows; setting it unconditionally would raise there.
            reuse_port = getattr(_socket, "SO_REUSEPORT", None)
            if reuse_port is not None:
                try:
                    sock.setsockopt(_socket.SOL_SOCKET, reuse_port, 1)
                except OSError:
                    pass  # present but refused (some kernels) -- not fatal

        if ipv6:
            sock.setsockopt(_socket.IPPROTO_IPV6, _socket.IPV6_MULTICAST_HOPS, ttl)
            sock.setsockopt(
                _socket.IPPROTO_IPV6, _socket.IPV6_MULTICAST_LOOP, int(loop)
            )
        else:
            sock.setsockopt(_socket.IPPROTO_IP, _socket.IP_MULTICAST_TTL, ttl)
            sock.setsockopt(_socket.IPPROTO_IP, _socket.IP_MULTICAST_LOOP, int(loop))

        # Pin outgoing traffic to the chosen adapter as well as incoming, or
        # sends leave by the default route while joins listen elsewhere.
        outgoing = _interface_address(interface, want_ipv6=ipv6)
        if outgoing and not ipv6:
            sock.setsockopt(
                _socket.IPPROTO_IP,
                _socket.IP_MULTICAST_IF,
                _socket.inet_aton(outgoing),
            )

        if bind:
            # "" rather than the group address: binding to the group works on
            # Linux but fails on Windows.
            sock.bind(("", port))

        for entry in groups:
            join_group(sock, entry, interface)
    except BaseException:
        sock.close()
        raise
    return sock
