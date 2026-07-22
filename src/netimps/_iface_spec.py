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

__all__ = ["interface_address"]


def interface_address(interface, want_ipv6: bool = False, strict: bool = True):
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
    from . import IPAddress, MACAddress, is_valid, try_parse
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
        match = next((iface for iface in get_interfaces() if iface.mac == wanted), None)
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
