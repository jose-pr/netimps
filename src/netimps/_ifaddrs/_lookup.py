"""Finding the local interface for an address, network, MAC, name or index; and local-host tests."""

from __future__ import annotations

import socket as _socket
from typing import Any, Iterator, Optional, Tuple, Union
from .._ip import (
    HostLike,
    IPAddress,
    IPAddressLike,
    IPInterface,
    IPNetwork,
    _as_address,
    _host_text,
    split_host,
    split_zone,
    unmap,
    get_hostname,
)
from .._mac import MACAddress
from .._parse import parse, try_parse
from ._cache import get_interfaces
from ._model import Interface


def _without_zone(address: "IPAddress") -> "IPAddress":
    """Drop an IPv6 ``%zone`` suffix, which enumeration never reports.

    ``ipaddress`` keeps the zone as part of the address, so
    ``IPv6Address("::1%1") != IPv6Address("::1")`` and a scoped address matches
    nothing in :func:`netimps.get_interfaces`. The zone identifies the
    *interface*, not the address, so it is stripped before any lookup and kept
    only in what is returned to the caller.
    """

    if not getattr(address, "scope_id", None):
        return address
    return parse(str(address).split("%", 1)[0], IPAddress)


def _zone_names(iface: "Interface", zone: str) -> bool:
    """True if ``zone`` identifies ``iface``.

    The one zone matcher behind :func:`interface_index`, :func:`interface_address`
    and :func:`netimps.get_interface`. Linux and Windows write an IPv6 zone as
    the numeric interface index, the BSDs as the adapter name; both are read.
    """
    if zone.isdigit():
        return bool(iface.index) and iface.index == int(zone)
    return iface.name == zone


InterfaceQuery = Union[
    Interface,
    IPAddressLike,
    IPInterface,
    IPNetwork,
    MACAddress,
]


def _classify_interface_query(query: "Optional[InterfaceQuery]") -> "Tuple[str, Any]":
    """Return the lookup kind and normalised value, or ``("invalid", None)``."""
    import ipaddress as _ipaddress

    if isinstance(query, Interface):
        return "interface", query
    if isinstance(query, MACAddress):
        return "mac", query
    if isinstance(query, (_ipaddress.IPv4Interface, _ipaddress.IPv6Interface)):
        return "address", query.ip
    if isinstance(query, (_ipaddress.IPv4Network, _ipaddress.IPv6Network)):
        return "network", query

    address = try_parse(query, IPAddress)
    if address is not None:
        return "address", address

    if isinstance(query, str) and "/" in query:
        network = try_parse(query, IPNetwork)
        if network is not None:
            return "network", network

    # MAC text cannot collide with a valid IP literal, and packed MAC bytes
    # have length 6 while packed IP addresses have length 4 or 16. Integers
    # are genuinely ambiguous, so those remain IP addresses unless callers
    # wrap them in MACAddress explicitly.
    if isinstance(query, (str, bytes)):
        mac = try_parse(query, MACAddress)
        if mac is not None:
            return "mac", mac
    # Text that is no address, network or MAC names an adapter.
    if isinstance(query, str) and query:
        return "name", query
    return "invalid", None


def _interfaces_for_query(
    kind: str,
    wanted: Any,
    cache: "Union[bool, float]" = False,
) -> "Iterator[Interface]":
    if kind == "interface":
        yield wanted
        return
    if kind == "invalid":
        return
    if kind == "index":
        enumerated = get_interfaces() if cache is False else get_interfaces(cache=cache)
        for iface in enumerated:
            if iface.index == wanted:
                yield iface
        return

    zone = getattr(wanted, "scope_id", None) if kind == "address" else None
    if zone:
        # ``ipaddress`` keeps the zone as part of the address, so a scoped
        # literal is equal to nothing enumeration reports. Compare on the bare
        # address and use the zone for what it actually is -- a name for the
        # adapter -- rather than letting it turn a local address into "not
        # mine".
        wanted = _without_zone(wanted)

    # The uncached path is the plain no-argument call, so a replacement for
    # `get_interfaces` that takes no `cache=` keyword still answers it.
    enumerated = get_interfaces() if cache is False else get_interfaces(cache=cache)
    for iface in enumerated:
        if kind == "mac":
            matches = iface.mac == wanted
        elif kind == "name":
            matches = iface.name == wanted
        elif kind == "address":
            matches = any(entry.ip == wanted for entry in iface.ips)
            if matches and zone:
                # A zone that contradicts the adapter holding the address is
                # not a match: the caller named a specific adapter.
                matches = _zone_names(iface, zone)
        else:
            matches = any(
                entry.version == wanted.version and entry.ip in wanted
                for entry in iface.ips
            )
        if matches:
            yield iface


#: The default of ``query``, telling "no query given" from an explicit ``None``
#: (which is an invalid query: no match).
_NO_QUERY: Any = object()


def _interface_target(
    query: "Optional[InterfaceQuery]", index: "Optional[int]"
) -> "Tuple[str, Any]":
    """The lookup kind and value for a query, or for ``index=`` instead of one."""
    if index is None:
        if query is _NO_QUERY:
            raise TypeError("pass a query or index=")
        return _classify_interface_query(query)
    if query is not _NO_QUERY:
        raise TypeError("pass a query or index=, not both")
    if not isinstance(index, int) or isinstance(index, bool):
        raise TypeError("index must be an int, not %r" % (type(index).__name__,))
    if index < 1:
        raise ValueError("index must be a positive interface index, got %r" % (index,))
    return "index", index


def iter_interfaces(
    query: "Optional[InterfaceQuery]" = _NO_QUERY,
    *,
    index: "Optional[int]" = None,
    cache: "Union[bool, float]" = False,
) -> "Iterator[Interface]":
    """Yield every local interface matching ``query``, in OS order.

    ``query`` may be an :class:`Interface` (yielded directly), an address, an
    ``IPInterface`` (matched by its exact ``.ip``), an ``IPNetwork`` (matched
    when it contains any assigned address), or a :class:`MACAddress`. Address-
    like strings, integers and packed bytes are accepted too; a slash-bearing
    string is interpreted as a network when it is not an address.

    MAC text and 6-byte packed values are recognised after IP parsing.
    Integer MACs must be wrapped in ``MACAddress`` because an integer is also
    a valid IP-address representation. Text that is no address, network or MAC
    is an **adapter name**; ``index=`` names an interface by its index instead
    of a ``query`` (an ``int`` query stays an address). Invalid queries and
    misses yield nothing. Each matching interface is yielded once even if
    several of its assigned addresses fall within a requested network.

    A ``%zone``-qualified IPv6 address (``fe80::1%15``, ``fe80::1%eth0``) is
    matched on its bare address and **filtered** by the zone, which names the
    adapter -- the index on Linux/Windows, the adapter name on BSD. That form
    is what ``getsockname()``, ``getaddrinfo`` and every OS tool emit, and
    matching it on the bare address keeps an address the library just reported
    from being denied as non-local. A zone naming an adapter that does not hold the
    address yields nothing, which is the honest answer to a contradiction.
    """
    kind, wanted = _interface_target(query, index)
    yield from _interfaces_for_query(kind, wanted, cache)


def get_interface(
    query: "Optional[InterfaceQuery]" = _NO_QUERY,
    *,
    index: "Optional[int]" = None,
    strict: bool = True,
    cache: "Union[bool, float]" = False,
) -> "Optional[Interface]":
    """Return the first local interface matching ``query``, or ``None``.

    The reverse of interface enumeration -- "a socket is bound here, which
    adapter is that?"::

        get_interface(sock.getsockname()[0])

    Accepts the same query forms as :func:`iter_interfaces`, an adapter name and
    ``index=`` among them (``get_interface(iface.name)``,
    ``get_interface(index=iface.index)``); singular lookup is exactly the first
    plural result. Since addresses can appear on more than one adapter
    (especially unscoped IPv6 link-local addresses) and so can a MAC (a teamed
    or virtual adapter), this returns the first in enumeration order: use the
    plural form when every match matters.

    :param strict: when True (the default), a miss returns ``None``. When
        False, an address or ``IPInterface`` miss produces a synthetic
        single-address ``Interface`` so a caller can still attribute traffic.
        Network and MAC misses cannot be synthesized honestly and remain
        ``None``.
    :param cache: reuse a recent enumeration rather than making the syscall --
        ``True`` for :data:`netimps.INTERFACE_CACHE_TTL` seconds, or a number
        for that TTL. **This is the argument a per-packet caller wants.** Each
        call otherwise enumerates every adapter, measured at 35-42 ms on a host
        with many of them.
        ``cache=0`` is a TTL of zero, so it enumerates and reseeds -- which is
        the whole of "force a refresh". :func:`netimps.clear_interface_cache`
        invalidates without a lookup.

    The synthetic interface is named ``"<unknown>"`` and carries a host route
    (``/32`` or ``/128``), matching how degraded enumeration reports itself.
    """
    kind, wanted = _interface_target(query, index)
    match = next(_interfaces_for_query(kind, wanted, cache), None)
    if match is not None or strict or kind != "address":
        return match

    built = _make_host_route(_without_zone(wanted))
    return Interface(name="<unknown>", ips=[built] if built else [])


def is_local_address(
    address: "IPAddressLike",
    *,
    cache: "Union[bool, float]" = False,
) -> bool:
    """Return whether ``address`` is loopback or assigned on this host.

    This is deliberately narrower than private, link-local, on-link, routable
    or reachable: those properties do not mean an address belongs to this
    machine. Text that is no address raises :class:`NetimpsValueError`, and a
    network or a value of another type :class:`TypeError`.

    A ``%zone`` suffix is honoured rather than rejected (see
    :func:`iter_interfaces`), so the address ``getsockname()`` hands back can be
    passed straight in.

    :param cache: reuse a recent enumeration -- see :func:`get_interface`. A
        loopback address short-circuits before any enumeration, so the cache
        only matters for the addresses that actually reach the adapter scan.
    """

    wanted = _as_address(address)
    if wanted.is_loopback:
        return True
    return next(iter_interfaces(wanted, cache=cache), None) is not None


def is_local_host(
    host: "HostLike",
    *,
    resolve: bool = False,
    cache: "Union[bool, float]" = False,
) -> bool:
    """Whether *host* names this machine.

    ::

        is_local_host("localhost")      # True
        is_local_host("127.0.0.1")      # True
        is_local_host("[::1]:22")       # True   -- a port is ignored
        is_local_host("10.0.0.5")       # True only if an interface holds it
        is_local_host("example.com")    # False, without asking the resolver

    True for a literal that :func:`is_local_address` accepts (loopback, or
    assigned to an interface; a ``%zone`` is ignored, and a v4-mapped address is
    judged as the v4 address inside; the short and numeric IPv4 spellings that
    ``inet_aton`` reads, such as ``127.1`` and ``2130706433``, are literals), for ``localhost`` and any ``*.localhost``
    (RFC 6761), and for this machine's own host name, compared without case and
    without a trailing dot.

    Any other name is **not resolved** unless ``resolve=True``: the answer then
    comes from the OS resolver (the hosts file included) and is true when any
    address it returns is local, and the fully qualified name of this machine
    counts as well. That can block on the network, which is why it is opt-in.

    *cache* is :func:`get_interfaces`'s, and matters only for the literals that
    reach the adapter scan. Never raises: text that is not a host, an empty one,
    or a name that does not resolve is simply not local.
    """
    try:
        name, _port = split_host(_host_text(host))
        name, _zone = split_zone(name)
    except (TypeError, ValueError):
        return False
    name = name.rstrip(".").lower()
    if not name:
        return False

    address = try_parse(name, IPAddress)
    if address is None:
        # inet_aton text (127.1, 2130706433, 0x7f.0.0.1) is a literal to the
        # socket layer, which sends it to the address it spells.
        try:
            address = parse(_socket.inet_ntoa(_socket.inet_aton(name)), IPAddress)
        except (OSError, ValueError):
            address = None
    if address is not None:
        return is_local_address(unmap(address), cache=cache)

    if name == "localhost" or name.endswith(".localhost"):
        return True
    # `socket.gethostname()` rather than `platform.node()`: the latter is a WMI
    # query on Windows, and this is asked of every name that is not a literal.
    if name == _socket.gethostname().lower():
        return True
    if not resolve:
        return False

    if name == get_hostname(fqdn=True).lower():
        return True
    try:
        found = _socket.getaddrinfo(name, None)
    except (OSError, UnicodeError):
        # UnicodeError: a name the IDNA codec refuses (an empty label, a label
        # over 63 octets) is no name of this machine.
        return False
    return any(
        is_local_address(unmap(parsed), cache=cache)
        for parsed in (
            try_parse(str(info[4][0]).split("%", 1)[0], IPAddress) for info in found
        )
        if parsed is not None
    )


def _make_host_route(address: "IPAddress") -> "Optional[IPInterface]":
    import ipaddress as _ipaddress

    try:
        return _ipaddress.ip_interface("%s/%d" % (address, address.max_prefixlen))
    except ValueError:
        return None
