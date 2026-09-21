"""Resolving a loose "which interface?" argument to a local address (internal).

**Private.** The public half of this is :meth:`netimps.Interface.primary_ip`,
which answers the same question when you already hold an ``Interface``. This
module only adds the coercion around it -- accepting a MAC, an adapter name or
a bare address as well -- which is a convenience for argument handling rather
than something worth putting in the public surface.

Several entry points let the caller name an interface loosely -- as an
:class:`Interface`, a :class:`MACAddress`, an adapter name, or a local address.
The OS never accepts all of those: ``ping -S`` and ``IP_MULTICAST_IF`` want an
*address*, IPv6 multicast wants an interface *index*, and only POSIX ``ping -I``
takes a name. Resolving in one place keeps every caller from re-deriving that.

Both functions apply the **same rule** to the same spec, so that a caller
choosing between them by address family does not get two different answers:
under ``strict=True`` an address spec must name an interface this host actually
has, exactly as an adapter name or a MAC must. They diverge only where they
must -- an address that no local interface claims can still be handed to the OS
verbatim, while an interface *index* cannot be invented -- and only when
``strict=False`` says the caller will check the result itself.

Re-exported from nothing -- this is used internally by ``_ping``,
``_multicast`` and ``_sockets``.
"""

from __future__ import annotations

from typing import Optional, Union

from ._ifaddrs import Interface
from ._ip import IPAddress
from ._mac import MACAddress

__all__ = ["interface_address", "interface_index"]

#: The loose "which interface?" spec every ``src=``/``interface=`` parameter
#: in the package accepts: an :class:`Interface`, a :class:`MACAddress` (or
#: MAC string), an adapter name, an address, or ``None`` for "no preference".
#: Kept private -- this documents an established, repeated parameter shape
#: rather than something a caller constructs or imports directly.
InterfaceSpec = Optional[Union[Interface, MACAddress, IPAddress, str]]


def _without_zone(address: "IPAddress") -> "IPAddress":
    """Drop an IPv6 ``%zone`` suffix, which enumeration never reports.

    ``ipaddress`` keeps the zone as part of the address, so
    ``IPv6Address("::1%1") != IPv6Address("::1")`` and a scoped address matches
    nothing in :func:`netimps.get_interfaces`. The zone identifies the
    *interface*, not the address, so it is stripped before any lookup and kept
    only in what is returned to the caller.
    """
    from . import IPAddress, parse

    if not getattr(address, "scope_id", None):
        return address
    return parse(str(address).split("%", 1)[0], IPAddress)


def _family_name(want_ipv6: bool) -> str:
    return "IPv6" if want_ipv6 else "IPv4"


def _enumeration_is_degraded() -> bool:
    """True when :func:`netimps.get_interfaces` fell back to hostname lookup.

    That path reports a single synthetic interface named ``"<unknown>"``
    carrying only the addresses ``getaddrinfo(gethostname())`` returns -- never
    ``127.0.0.1``, usually not a VPN or container address. Checking an address
    against *that* answers a different question, so the locality rule below
    steps aside rather than rejecting addresses the host really has.
    """
    from ._ifaddrs import get_interfaces

    return any(iface.name == "<unknown>" for iface in get_interfaces())


def interface_address(
    interface: "InterfaceSpec",
    want_ipv6: "Optional[bool]" = False,
    strict: bool = True,
) -> "Optional[IPAddress]":
    """Reduce an interface spec to a local address.

    Returns an ``IPv4Address``/``IPv6Address``, never a string -- every netimps
    function that yields an address yields the parsed object, and the caller
    applies ``str()`` at the OS boundary where one is needed.

    :param interface: an :class:`Interface`, a :class:`MACAddress` (or MAC
        string), an adapter name, an address, or ``None``.
    :param want_ipv6: the family the caller can use -- ``False`` for IPv4,
        ``True`` for IPv6, ``None`` for "either". It picks which address of an
        ``Interface`` to take **and** is checked against a bare address spec,
        which it used to ignore: a wrong-family literal otherwise sailed
        through to ``inet_aton`` or ``bind`` and failed there instead, naming
        neither the spec nor the family that was wanted.
    :param strict: when True (the default) an unresolvable spec raises
        :class:`ValueError`; when False it returns the best answer it has and
        never raises.

    ``None`` in gives ``None`` out -- "no preference", which callers translate
    into leaving the flag off entirely.

    A non-loopback address is preferred when an ``Interface`` has several; a
    loopback one is used only if that is genuinely all it has.

    The ``strict`` split exists because the two original callers disagreed:
    multicast raised on an unknown interface (a join to the wrong adapter
    silently receives nothing, so failing loudly is right), while ``ping``
    returned ``None`` and reported a falsy result. Both are preserved, and the
    split now also decides how hard a bare *address* spec is checked:

    * ``strict=True`` -- the address must be of the wanted family and must be
      held by a local interface, the same rule :func:`interface_index` applies.
      This is for callers that hand the result straight to the OS as an
      adapter selector (``bind``, ``IP_MULTICAST_IF``, an IPv4 ``mreq``),
      where an address no adapter holds is guaranteed to fail; saying so here
      beats a bare ``EADDRNOTAVAIL`` from three frames away.
    * ``strict=False`` -- the address is returned as given, family and all.
      The tolerant callers (``ping -I``, UDP source pinning) inspect it and do
      something better than dropping it: ``_udp`` turns an IPv4 source for an
      IPv6 socket into a v4-mapped one, and rejects the reverse with its own
      message.
    """
    from . import IPAddress, MACAddress, interface_for, is_valid, try_parse
    from ._ifaddrs import Interface, get_interfaces

    if interface is None:
        return None

    def _fail(message: str):
        if strict:
            raise ValueError(message)
        return None

    # A MAC names an adapter, so find the one carrying it. Checked before the
    # name branch because a MAC string is not an adapter name.
    if isinstance(interface, MACAddress) or (
        isinstance(interface, str) and is_valid(interface, MACAddress)
    ):
        wanted = MACAddress(interface)
        match = interface_for(wanted)
        if match is None:
            return _fail("no interface with MAC %s" % (wanted,))
        interface = match

    # A string that is not an address literal must be an adapter name. Looking
    # it up here beats a confusing setsockopt/subprocess error later.
    if isinstance(interface, str) and not is_valid(interface, IPAddress):
        match = next(
            (iface for iface in get_interfaces() if iface.name == interface), None
        )
        if match is None:
            return _fail("no interface named %r" % (interface,))
        interface = match

    if isinstance(interface, Interface):
        # The Interface -> address half is a method on the type itself; this
        # function only adds the loose-spec coercion around it.
        chosen = interface.primary_ip(ipv6=bool(want_ipv6))
        if chosen is None and want_ipv6 is None:
            # "Either family": try the other one before giving up.
            chosen = interface.primary_ip(ipv6=True)
        if chosen is None:
            return _fail(
                "interface %r has no %s address"
                % (
                    interface.name,
                    "IPv4 or IPv6" if want_ipv6 is None else _family_name(want_ipv6),
                )
            )
        return chosen.ip

    # Anything else must already be an address (object or literal).
    parsed = try_parse(str(interface).strip(), IPAddress)
    if parsed is None:
        return _fail("cannot resolve %r to a local address" % (interface,))

    if want_ipv6 is not None and (parsed.version == 6) != want_ipv6:
        if not strict:
            return parsed  # the caller checks the family itself; see above.
        return _fail(
            "%s is an IPv%d address, but an %s one was requested"
            % (parsed, parsed.version, _family_name(want_ipv6))
        )

    # An address spec names an interface just as a name or a MAC does, so it
    # is held to the same rule -- otherwise the very same spec is accepted for
    # IPv4 (which wants an address) and rejected for IPv6 (which wants an
    # index), which is interface_index's behaviour below.
    bare = _without_zone(parsed)
    if strict and interface_for(bare) is None and not _enumeration_is_degraded():
        return _fail("no local interface holds address %s" % (bare,))
    return parsed


def interface_index(interface: "InterfaceSpec", strict: bool = True) -> "Optional[int]":
    """Reduce an interface spec to its OS interface index.

    The index-shaped sibling of :func:`interface_address`, for the OS
    interfaces that identify an adapter by number rather than by address:
    ``IPV6_JOIN_GROUP``/``IPV6_LEAVE_GROUP``'s ``mreq`` and
    ``IPV6_MULTICAST_IF`` all take an index. Reducing such a spec to an
    address first is not a lossy shortcut but an outright wrong answer --
    ``if_nametoindex("2001:db8::5")`` raises, leaving index ``0``, which the
    kernel reads as "choose by routing table".

    :param interface: an :class:`Interface`, a :class:`MACAddress` (or MAC
        string), an adapter name, an address held by a local interface, or
        ``None``.
    :param strict: when True (the default) a spec that names no local
        interface -- or one the platform reports no index for -- raises
        :class:`ValueError`; when False it returns ``None``.

    ``None`` in gives ``None`` out -- "no preference", which callers translate
    into leaving the index at ``0`` and letting the kernel pick.

    An index of ``0`` is never returned as a value: ``0`` *is* the kernel's
    "pick for me", so reporting it for an adapter the caller explicitly named
    would recreate the silent wrong-adapter failure this exists to prevent.

    A ``%zone`` suffix is **honoured, not ignored**: it is the one part of a
    scoped address that names an interface, which is exactly what is being
    asked for here. Linux and Windows spell the zone as the numeric index and
    the BSDs as the adapter name, and both are read. Without this, every
    scoped literal failed the lookup outright -- ``ipaddress`` keeps the zone
    as part of the address, so ``fe80::1%12`` matches no enumerated address.
    """
    from . import IPAddress, MACAddress, interface_for, is_valid, try_parse
    from ._ifaddrs import Interface, get_interfaces

    if interface is None:
        return None

    def _fail(message: str):
        if strict:
            raise ValueError(message)
        return None

    match: "Optional[Interface]" = None
    if isinstance(interface, Interface):
        match = interface
    elif isinstance(interface, MACAddress) or (
        isinstance(interface, str) and is_valid(interface, MACAddress)
    ):
        wanted = MACAddress(interface)
        match = interface_for(wanted)
        if match is None:
            return _fail("no interface with MAC %s" % (wanted,))
    elif isinstance(interface, str) and not is_valid(interface, IPAddress):
        # An adapter name. Resolved through get_interfaces() rather than
        # socket.if_nametoindex() so the Windows *friendly* name works too --
        # if_nametoindex there wants the adapter's GUID-ish system name.
        match = next(
            (iface for iface in get_interfaces() if iface.name == interface), None
        )
        if match is None:
            return _fail("no interface named %r" % (interface,))
    else:
        address = try_parse(str(interface).strip(), IPAddress)
        if address is None:
            return _fail("cannot resolve %r to a local interface" % (interface,))
        zone = getattr(address, "scope_id", None)
        if zone:
            if zone.isdigit():
                # The OS wrote this index itself; take it at face value.
                index = int(zone)
                if index:
                    return index
            else:
                named = next(
                    (iface for iface in get_interfaces() if iface.name == zone), None
                )
                if named is not None and named.index:
                    return named.index
            address = _without_zone(address)
        match = interface_for(address)
        if match is None:
            return _fail("no local interface holds address %s" % (address,))

    if not match.index:
        return _fail("interface %r reports no index on this platform" % (match.name,))
    return match.index
