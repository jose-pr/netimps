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
* **The two families name an adapter differently.** IPv4 identifies it by a
  local *address* (``IP_ADD_MEMBERSHIP``'s ``imr_interface``,
  ``IP_MULTICAST_IF``); IPv6 identifies it by interface *index*
  (``IPV6_JOIN_GROUP``'s ``ipv6mr_interface``, ``IPV6_MULTICAST_IF``).
  Feeding an address to the v6 side does not fail loudly -- it lands as index
  ``0``, which means "kernel's choice", i.e. the default this module exists
  to let you override.
* **``SO_REUSEPORT`` does not exist on Windows.** Code that sets it
  unconditionally raises there, so it is applied only where present.
* **Default TTL is 1**, confining traffic to the local link. Raising it is a
  deliberate act, not a detail to leave at whatever the OS chose.
"""

from __future__ import annotations

import socket as _socket
import sys as _sys
import struct as _struct
from typing import List, Optional, Union

from ._iface_spec import InterfaceSpec, interface_address as _interface_address
from ._iface_spec import interface_index as _interface_index
from ._ip import AddressLike

__all__ = ["multicast_socket", "join_group", "leave_group", "is_multicast"]


def is_multicast(address: "AddressLike") -> bool:
    """True if ``address`` is a multicast group (``224.0.0.0/4`` or ``ff00::/8``).

    ::

        is_multicast("224.0.0.251")   # True  -- mDNS
        is_multicast("ff02::fb")      # True
        is_multicast("10.0.0.1")      # False

    Accepts everything :data:`AddressLike` does, including an
    :class:`IPv4Interface`/:class:`IPv6Interface` -- its ``.ip`` is tested::

        is_multicast(IPv4Interface("239.1.2.3/32"))   # True

    That matters because this is the gatekeeper :func:`join_group` and
    :func:`leave_group` use. Testing the interface object directly asked
    whether a *network* was multicast, which it never is, so a real group
    passed in the form every other function here accepts was rejected as "not
    a multicast group".

    Never raises: anything unparseable is ``False``.
    """
    from . import IPAddress, try_parse

    from ._ip import _dst_argument

    try:
        address = _dst_argument(address)
    except (TypeError, ValueError):
        return False
    parsed = try_parse(address, IPAddress)
    return bool(parsed is not None and parsed.is_multicast)


#: Multicast scope values (low nibble of the address's second byte, RFC 4291):
#: 1 interface-local, 2 link-local, 5 site-local, e global. At or below
#: link-local the address means nothing without an interface.
_LINK_LOCAL_SCOPE = 0x2

#: Platforms whose kernel will not pick a scope for a link-local IPv6 join.
_NEEDS_EXPLICIT_V6_SCOPE = not (
    _sys.platform == "win32" or _sys.platform.startswith("linux")
)


def _default_v6_scope(group: str) -> int:
    """An interface index for a link-local IPv6 join, where 0 will not do.

    Index ``0`` means "kernel's choice", which is the right default and works
    on Linux and Windows. macOS/BSD will not make that choice for a
    **link-local** group -- ``ff02::/16`` has no meaning without a scope, so the
    join fails with ``EADDRNOTAVAIL`` rather than picking for you. Measured:
    ``multicast_socket("ff02::fb")`` joins on Linux and Windows (both leaving
    ``IPV6_MULTICAST_IF`` at 0) and raises ``OSError 49`` on macOS.

    So this supplies a scope only where the kernel refuses to, and only when
    the caller did not name one -- an explicit ``interface=`` always wins, on
    every platform. Returning ``0`` leaves the behaviour exactly as it was.

    The pick mirrors what a kernel would do: the first non-loopback adapter
    that actually carries a link-local address, in enumeration order. That is a
    guess on a multi-homed host, which is precisely why ``interface=`` is
    documented as strongly recommended there -- but a guess that joins beats an
    error that does not, and the caller keeps the override.
    """
    if not _NEEDS_EXPLICIT_V6_SCOPE:
        return 0
    from . import try_parse

    parsed = try_parse(group)
    if parsed is None or parsed.version != 6 or not parsed.is_multicast:
        return 0
    # The scope of a multicast address is the low nibble of its second byte --
    # 1 interface-local, 2 link-local, 5 site-local, e global. It is NOT
    # `is_link_local`, which means the `fe80::/10` **unicast** range and is
    # False for `ff02::fb`; using it here is why this returned 0 and the join
    # went on failing on macOS. Only the scopes that cannot be routed need an
    # interface to be meaningful.
    if parsed.packed[1] & 0x0F > _LINK_LOCAL_SCOPE:
        return 0

    from . import get_interfaces

    for iface in get_interfaces():
        if iface.is_loopback or not iface.index:
            continue
        if any(
            address.ip.version == 6 and address.ip.is_link_local
            for address in iface.ips
        ):
            return iface.index
    return 0


def _membership_request(group: str, interface: "InterfaceSpec", ipv6: bool):
    """Build the mreq structure for IP_ADD_MEMBERSHIP / IPV6_JOIN_GROUP.

    Resolving the interface spec lives here rather than in the callers
    because the two families need *different* resolutions of the same spec:
    IPv4 wants a local address, IPv6 wants an interface index.
    """
    if ipv6:
        index = _interface_index(interface) or 0
        if index == 0:
            index = _default_v6_scope(group)
        return _socket.inet_pton(_socket.AF_INET6, group) + _struct.pack("@I", index)

    address = _interface_address(interface, want_ipv6=False)
    local = "0.0.0.0" if address is None else str(address)
    return _struct.pack("4s4s", _socket.inet_aton(group), _socket.inet_aton(local))


def join_group(
    sock: "_socket.socket", group: str, interface: "InterfaceSpec" = None
) -> None:
    """Join ``group`` on ``sock``, optionally via a specific ``interface``.

    ``interface`` accepts an :class:`Interface`, a MAC, an adapter name or a
    local address. Without one the kernel chooses by routing table, which on a
    host with VMs or a VPN is often the wrong adapter -- and the failure is
    silent: the socket simply never receives.

    The spec is resolved per family: to a local **address** for an IPv4
    group, to an interface **index** for an IPv6 one, since that is what each
    ``mreq`` carries.

    Raises :class:`ValueError` for a non-multicast group, or for an interface
    that resolves to no usable address (IPv4) or no index (IPv6), and
    :class:`OSError` if the kernel rejects the join.
    """
    if not is_multicast(group):
        raise ValueError("%r is not a multicast group" % (group,))

    ipv6 = ":" in group
    request = _membership_request(group, interface, ipv6)
    if ipv6:
        sock.setsockopt(_socket.IPPROTO_IPV6, _socket.IPV6_JOIN_GROUP, request)
    else:
        sock.setsockopt(_socket.IPPROTO_IP, _socket.IP_ADD_MEMBERSHIP, request)


def leave_group(
    sock: "_socket.socket", group: str, interface: "InterfaceSpec" = None
) -> None:
    """Leave ``group`` on ``sock``. The inverse of :func:`join_group`.

    Closing the socket drops membership too, so this is only needed to leave a
    group while keeping the socket open.
    """
    if not is_multicast(group):
        raise ValueError("%r is not a multicast group" % (group,))

    ipv6 = ":" in group
    request = _membership_request(group, interface, ipv6)
    if ipv6:
        sock.setsockopt(_socket.IPPROTO_IPV6, _socket.IPV6_LEAVE_GROUP, request)
    else:
        sock.setsockopt(_socket.IPPROTO_IP, _socket.IP_DROP_MEMBERSHIP, request)


def multicast_socket(
    group: "Union[str, List[str], None]" = None,
    port: int = 0,
    interface: "InterfaceSpec" = None,
    ttl: int = 1,
    loop: bool = True,
    bind: bool = True,
    reuse: bool = True,
    ipv6: "Optional[bool]" = None,
) -> "_socket.socket":
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
        routing-table default is frequently the wrong adapter. Pins outgoing
        traffic as well as the joins (``IP_MULTICAST_IF`` for IPv4,
        ``IPV6_MULTICAST_IF`` for IPv6), so sends and receives cannot end up
        on different adapters.
    :param ttl: hop limit for outgoing datagrams. The default of **1 keeps
        traffic on the local link**; raise it deliberately to cross routers.
    :param loop: whether this host receives its own transmissions. ``True``
        (the default) is what you want when sender and listener share a host.
    :param bind: bind to ``port``. Binding to ``""`` rather than the group
        address, because binding to the group fails on Windows.
    :param reuse: set ``SO_REUSEADDR`` (plus ``SO_REUSEPORT`` where it exists),
        so several listeners can share the port. ``SO_REUSEPORT`` is absent on
        Windows and is skipped there rather than raising.

    :param ipv6: force the address family. ``None`` (the default) takes it from
        ``group``, which is what you want whenever there is one::

            multicast_socket(ttl=32, bind=False)              # IPv4 sender
            multicast_socket(ttl=32, bind=False, ipv6=True)   # IPv6 sender

        It exists for the send-only case above, where there is no group to
        infer from: that socket used to be IPv4 unconditionally, so an IPv6
        sender was unreachable through this function. Passing a value that
        contradicts ``group`` raises rather than quietly winning.

    The caller owns the socket and should close it; closing drops membership.
    Raises :class:`ValueError` for a non-multicast group, for groups of mixed
    address families (one socket has one family -- open two), for an ``ipv6``
    that contradicts ``group``, and :class:`OSError` if binding or joining
    fails.
    """
    groups = [group] if isinstance(group, str) else list(group or [])
    families = {":" in entry for entry in groups}
    if len(families) > 1:
        # One socket has one family. Picking either and letting the other join
        # fail surfaces as an opaque OSError from deep inside setsockopt, which
        # says nothing about the real mistake.
        raise ValueError(
            "groups must be all IPv4 or all IPv6, got %r -- one socket has one "
            "address family; open two" % (groups,)
        )
    if ipv6 is None:
        # No groups at all is the send-only case, and `any()` over an empty list
        # is False -- so a send-only socket was silently always IPv4, and the
        # documented `multicast_socket(ttl=32, bind=False)` sender could never
        # be given an IPv6 hop limit or used to reach an IPv6 group.
        ipv6 = bool(families and families.pop())
    family = _socket.AF_INET6 if ipv6 else _socket.AF_INET
    if groups and any((":" in entry) != ipv6 for entry in groups):
        raise ValueError(
            "ipv6=%r contradicts the address family of %r" % (ipv6, groups)
        )

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
        # sends leave by the default route while joins listen elsewhere. The
        # option is per-family: IPv4 names the adapter by local address, IPv6
        # by interface index.
        if interface is not None:
            if ipv6:
                index = _interface_index(interface)
                if index:
                    sock.setsockopt(
                        _socket.IPPROTO_IPV6,
                        _socket.IPV6_MULTICAST_IF,
                        _struct.pack("@I", index),
                    )
            else:
                outgoing = _interface_address(interface, want_ipv6=False)
                if outgoing is not None:
                    sock.setsockopt(
                        _socket.IPPROTO_IP,
                        _socket.IP_MULTICAST_IF,
                        _socket.inet_aton(str(outgoing)),
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
