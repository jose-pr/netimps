"""Questions asked of the addresses on this host: broadcast, unicast, and one row per address."""

from __future__ import annotations

import socket as _socket
from typing import Iterable, Iterator, Optional, Sequence, Tuple, Union
from .._ip import (
    IPAddressLike,
    IPv4Address,
    _as_address,
    _family_argument,
    is_wildcard,
    unmap,
)
from ._cache import get_interfaces
from ._model import Interface, _IPInterface


def is_broadcast(
    address: "IPAddressLike",
    interface: "Optional[Interface]" = None,
    *,
    cache: "Union[bool, float]" = False,
) -> bool:
    """Whether *address* is an IPv4 broadcast address, limited or subnet.

    The question a wildcard-bound UDP server asks about
    :attr:`netimps.Datagram.destination` before answering: RFC 1123 says a TFTP
    server must ignore a broadcast request, and DHCP has to tell a broadcast
    DISCOVER from a unicast RENEW.

    Pass ``interface`` whenever the caller has it -- a
    :attr:`netimps.Datagram.interface`, say. Without it this enumerates every
    adapter, measured at **1.25 ms against 0.004 ms**, and a server asking the
    question of every request pays that per packet. ``cache=`` is the fallback
    for when the interface is genuinely unknown; it means what it means on
    :func:`get_interfaces`.

    ``255.255.255.255`` (limited broadcast) needs no context and short-circuits
    before any of that. The **subnet** broadcast does: ``10.0.0.255`` is only a
    broadcast if some interface carries ``10.0.0.0/24``, so this consults
    interface prefixes -- which is why it lives
    here and not in :mod:`netimps._ip`. Pass ``interface`` to check one adapter
    (the arrival interface, from ``Datagram.interface``); omit it to check every
    local one, which costs an enumeration.

    A **v4-mapped** address is unmapped first, because a dual-stack listener
    reports an IPv4 arrival as ``::ffff:a.b.c.d`` and the broadcast question is
    about the v4 address inside.

    IPv6 has **no broadcast** -- it uses multicast instead -- so a genuine v6
    address is always ``False`` here. :func:`netimps.is_multicast` is the
    companion predicate, kept separate on purpose: "do not answer this" is
    usually ``is_broadcast(a, i) or is_multicast(a)``, and one name meaning both
    would hide which of the two it matched.

    :raises NetimpsValueError: for text that is no address.
    :raises TypeError: for a network or a value of another type.
    """
    parsed = unmap(_as_address(address))
    if not isinstance(parsed, IPv4Address):
        return False

    # The limited broadcast, which needs no interface context at all.
    if parsed == IPv4Address("255.255.255.255"):
        return True

    if interface is not None:
        candidates: "Iterable[Interface]" = [interface]
    elif cache is False:
        candidates = get_interfaces()
    else:
        candidates = get_interfaces(cache=cache)
    for entry in candidates:
        for bound in getattr(entry, "ips", ()) or ():
            network = getattr(bound, "network", None)
            if network is None or network.version != 4:
                continue
            # A /31 or /32 has no broadcast address distinct from its hosts;
            # `broadcast_address` still answers, so size it out explicitly.
            if network.prefixlen >= 31:
                continue
            if parsed == network.broadcast_address:
                return True
    return False


def is_unicast(
    address: "IPAddressLike",
    interface: "Optional[Interface]" = None,
    *,
    cache: "Union[bool, float]" = False,
) -> bool:
    """Whether a datagram sent to *address* was meant for one host.

    False for the wildcard, a multicast group, and a broadcast (limited or
    subnet); true for everything else. This is the "answer it or ignore it"
    question a DHCP or TFTP server asks of :attr:`netimps.Datagram.destination`,
    which callers wrote as ``not (is_broadcast(...) or is_multicast(...))`` plus
    a wildcard test of their own.

    *interface* and *cache* mean what they mean on :func:`is_broadcast`, the one
    part that can enumerate. A v4-mapped address is judged as the v4 address
    inside it.

    :raises NetimpsValueError: for text that is no address.
    :raises TypeError: for a network or a value of another type.
    """
    if isinstance(address, str):
        address = address.split("%", 1)[0]
    parsed = unmap(_as_address(address))
    if is_wildcard(parsed) or parsed.is_multicast:
        return False
    return not is_broadcast(parsed, interface, cache=cache)


def iter_addresses(
    interfaces: "Optional[Iterable[Interface]]" = None,
    *,
    family: "Optional[int]" = None,
    cache: "Union[bool, float]" = False,
) -> "Iterator[Tuple[Interface, _IPInterface]]":
    """Yield ``(interface, address)`` once per address, not once per adapter.

    :func:`get_interfaces` groups every address under its adapter, which is the
    right shape for "describe this host". Callers that filter or act *per
    address* -- picking a bind target, excluding link-local, matching a subnet
    -- want the flattened view instead, and would otherwise write the same
    nested loop each time::

        for iface, addr in iter_addresses():
            if addr.ip in some_network:
                bind_to(addr.ip)

    :param interfaces: reuse an existing enumeration instead of calling
        :func:`get_interfaces` again. Worth passing in a loop, since
        enumeration is a syscall.
    :param family: ``4`` or ``AF_INET``, ``6`` or ``AF_INET6`` to yield only
        that family; ``None`` for both. Anything else raises
        :class:`ValueError` **when this function is called**, not on the first
        ``next()``: a generator that validates lazily reports a bad argument
        from somewhere the traceback does not name the caller.
    :param cache: when *interfaces* is not given, reuse a recent enumeration, as
        :func:`get_interfaces` does. ``False`` (the default) enumerates when the
        first address is asked for. Ignored when *interfaces* is given.

    The ``interface`` is the full :class:`Interface`, so its name, MAC and MTU
    stay reachable -- the flattening loses no information.
    """
    normalised = _family_argument(family)
    version = (
        None if normalised is None else (4 if normalised == _socket.AF_INET else 6)
    )
    return _iter_addresses(interfaces, version, cache)


def _iter_addresses(
    interfaces: "Optional[Iterable[Interface]]",
    family: "Optional[int]",
    cache: "Union[bool, float]" = False,
) -> "Iterator[Tuple[Interface, _IPInterface]]":
    """The generator half of :func:`iter_addresses`, after validation."""
    if interfaces is None:
        interfaces = get_interfaces() if cache is False else get_interfaces(cache=cache)
    for iface in interfaces:
        entries: "Sequence[_IPInterface]"
        if family == 4:
            entries = iface.ipv4
        elif family == 6:
            entries = iface.ipv6
        else:
            entries = iface.ips
        for entry in entries:
            yield iface, entry
