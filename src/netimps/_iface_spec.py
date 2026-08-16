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


def interface_address(
    interface: "InterfaceSpec", want_ipv6: bool = False, strict: bool = True
) -> "Optional[IPAddress]":
    """Reduce an interface spec to a local address.

    Returns an ``IPv4Address``/``IPv6Address``, never a string -- every netimps
    function that yields an address yields the parsed object, and the caller
    applies ``str()`` at the OS boundary where one is needed.

    :param interface: an :class:`Interface`, a :class:`MACAddress` (or MAC
        string), an adapter name, an address, or ``None``.
    :param want_ipv6: pick the IPv6 address of an ``Interface`` rather than its
        IPv4 one.
    :param strict: when True (the default) an unresolvable spec raises
        :class:`ValueError`; when False it returns ``None``.

    ``None`` in gives ``None`` out -- "no preference", which callers translate
    into leaving the flag off entirely.

    A non-loopback address is preferred when an ``Interface`` has several; a
    loopback one is used only if that is genuinely all it has.

    The ``strict`` split exists because the two original callers disagreed:
    multicast raised on an unknown interface (a join to the wrong adapter
    silently receives nothing, so failing loudly is right), while ``ping``
    returned ``None`` and reported a falsy result. Both are preserved.
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
        chosen = interface.primary_ip(ipv6=want_ipv6)
        if chosen is None:
            return _fail(
                "interface %r has no %s address"
                % (interface.name, "IPv6" if want_ipv6 else "IPv4")
            )
        return chosen.ip

    # Anything else must already be an address (object or literal).
    parsed = try_parse(str(interface).strip(), IPAddress)
    if parsed is None:
        return _fail("cannot resolve %r to a local address" % (interface,))
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
        match = interface_for(address)
        if match is None:
            return _fail("no local interface holds address %s" % (address,))

    if not match.index:
        return _fail("interface %r reports no index on this platform" % (match.name,))
    return match.index
