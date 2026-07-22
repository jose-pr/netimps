"""netimps -- small, self-contained network utilities.

A thin, typed convenience layer over the standard library's :mod:`ipaddress`
plus a handful of host helpers (DNS lookup, ping, interface discovery). One
flat import surface; the only runtime dependency is ``dnspython``, used solely
inside :func:`resolve`.

::

    import netimps

    netimps.IPAddr("10.0.0.5")                          # -> IPv4Address
    netimps.MACAddress("AA:BB:CC:DD:EE:FF").as_str("-")
    netimps.resolve("example.com", "aaaa")
    for iface in netimps.get_interfaces():
        print(iface.name, iface.mac, iface.ips)

Types vs factories
------------------
The noun-shaped names are **types** -- the v4/v6 unions you annotate with,
reading the way :class:`ipaddress.IPv4Address` does::

    def route(dst: netimps.IPAddress, via: netimps.IPNetwork) -> None: ...

The short names are the **factories** that parse and build those values,
mirroring the stdlib's ``ip_address()`` in being callables rather than types::

    IPAddr(value)   IPIface(value)   IPNet(value)

All IP/network values are the concrete :mod:`ipaddress` classes, so
``.exploded``, ``.network_address``, ``.netmask`` and ``addr in network``
membership all behave exactly as the stdlib does.
"""

from __future__ import annotations

import ipaddress as _ipaddress
import math as _math
import os as _os
import platform as _platform
import re as _re
import socket as _socket
from subprocess import TimeoutExpired as _SubprocessTimeout
from subprocess import run as _run
from typing import TYPE_CHECKING, Any, Callable, List, Optional, Type, TypeVar, Union
from typing import get_origin as _typing_get_origin

if TYPE_CHECKING:
    # TypeGuard landed in typing at 3.10 and typing_extensions before that.
    # Under TYPE_CHECKING only, so 3.9 needs no runtime dependency: type
    # checkers supply typing_extensions themselves.
    try:
        from typing import TypeGuard
    except ImportError:  # pragma: no cover - 3.9
        from typing_extensions import TypeGuard

# Re-export the concrete stdlib types so consumers can annotate with them.
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)

__all__ = [
    # Types: the v4/v6 unions you annotate with, plus the stdlib concretes.
    "IPAddress",
    "IPInterface",
    "IPNetwork",
    "IPv4Address",
    "IPv4Interface",
    "IPv4Network",
    "IPv6Address",
    "IPv6Interface",
    "IPv6Network",
    "MACAddress",
    "IPAddressLike",
    "IPNetworkLike",
    "MACLike",
    # Factories: callables that parse and return the above.
    "IPAddr",
    "IPIface",
    "IPNet",
    "try_parse",
    "is_valid",
    "is_valid_ip",
    "is_valid_network",
    "is_valid_mac",
    "get_ip",
    "is_link_scoped",
    "get_default_port",
    "port_scheme",
    "register_port",
    "resolve",
    "ping",
    "Interface",
    "get_interfaces",
    "HOST_DN",
]

__version__ = "0.2.0"

#: Fully-qualified (or short) name of the host running this process.
HOST_DN = _platform.node()

# ---------------------------------------------------------------------------
# Public type aliases
# ---------------------------------------------------------------------------
# The noun-shaped names are the *types* -- ``IPAddress`` is the v4/v6 union you
# annotate with, matching how ``ipaddress.IPv4Address`` and friends read. The
# short ``IPAddr``/``IPIface``/``IPNet`` spellings are the *factory functions*
# further down, mirroring the stdlib's lowercase ``ip_address()`` in being
# callables rather than types.

#: Either concrete address type: ``IPv4Address | IPv6Address``.
IPAddress = Union[IPv4Address, IPv6Address]

#: Either concrete interface type (address + prefix).
IPInterface = Union[IPv4Interface, IPv6Interface]

#: Either concrete network type.
IPNetwork = Union[IPv4Network, IPv6Network]

#: Anything :func:`IPAddr` accepts.
IPAddressLike = Union[str, int, IPv4Address, IPv6Address]

#: Anything :func:`IPNet` accepts.
IPNetworkLike = Union[str, int, IPv4Network, IPv6Network, IPv4Address, IPv6Address]

#: Anything :class:`MACAddress` accepts.
MACLike = Union[str, int, bytes, "MACAddress"]

# Internal aliases kept as runtime objects (not just annotations) so they read
# well in tracebacks; the public spellings above are what callers should use.
_AddressValue = Union[str, int, "_ipaddress._BaseAddress"]
_NetworkValue = Union[str, int, "_ipaddress._BaseNetwork", "_ipaddress._BaseAddress"]


# ---------------------------------------------------------------------------
# IP address / interface / network factories
# ---------------------------------------------------------------------------


def IPAddr(value: _AddressValue) -> IPAddress:
    """Return an :class:`ipaddress.IPv4Address`/:class:`IPv6Address`.

    Accepts a string (``"10.0.0.5"``), a packed/integer form, or an existing
    address object (returned as-is by the stdlib). This is a factory function,
    not a class -- ``isinstance(x, IPAddr)`` is not meaningful. Annotate with
    the :data:`IPAddress` union instead, and test against the concrete
    ``IPv4Address``/``IPv6Address``.
    """
    return _ipaddress.ip_address(value)


def IPIface(value: _AddressValue) -> IPInterface:
    """Return an :class:`ipaddress.IPv4Interface`/:class:`IPv6Interface`.

    An interface carries both a host address and its network, exposing ``.ip``,
    ``.netmask`` and ``.network`` (each with ``.exploded``), e.g.::

        IPIface("10.0.0.5/24").network.network_address.exploded

    Annotate with the :data:`IPInterface` union.
    """
    return _ipaddress.ip_interface(value)


def IPNet(value: _NetworkValue, strict: bool = False) -> IPNetwork:
    """Return an :class:`ipaddress.IPv4Network`/:class:`IPv6Network`.

    Defaults to ``strict=False`` so a host address with a prefix (e.g.
    ``"10.0.0.5/24"``) is accepted and normalised to its network rather than
    raising. Supports ``.network_address``, ``.netmask`` and ``addr in network``
    membership tests.
    """
    return _ipaddress.ip_network(value, strict=strict)


_T = TypeVar("_T")

# Result types accepted in a `parser` position, mapped to the callable that
# builds them, so callers can pass the *type* they want (``try_parse(v,
# IPAddress)``) rather than recall the factory's name.
#
# Only result types belong here. The ``*Like`` aliases describe accepted
# *input*, so mapping them would conflate "what goes in" with "what comes out";
# MACAddress and the factories are already callable and need no entry.
_PARSER_FOR_TYPE = {
    # The v4/v6 unions -- not callable, so these would be a TypeError otherwise.
    # They accept either family, which is the point of the union.
    IPAddress: IPAddr,
    IPInterface: IPIface,
    IPNetwork: IPNet,
}


def _family_strict(factory, wanted):
    """Parse with ``factory``, then require the result to be of type ``wanted``.

    The concrete classes need an entry after all, for two reasons:

    * ``IPv4Network("10.0.0.5/24")`` raises, because the stdlib constructors
      default to ``strict=True`` while :func:`IPNet` deliberately does not.
      Routing through the factory keeps host-bits-set input working uniformly.
    * The family must still be enforced, so ``IPv4Address("::1")`` stays a
      rejection rather than silently returning an ``IPv6Address``.
    """

    def parse(value):
        result = factory(value)
        if not isinstance(result, wanted):
            raise ValueError("%r is not a %s" % (value, wanted.__name__))
        return result

    return parse


# The concrete classes: same permissive parsing as the factories, but the
# requested family is enforced -- ask for v4 and v6 input is rejected, never
# quietly converted.
_PARSER_FOR_TYPE.update(
    {
        IPv4Address: _family_strict(IPAddr, IPv4Address),
        IPv6Address: _family_strict(IPAddr, IPv6Address),
        IPv4Interface: _family_strict(IPIface, IPv4Interface),
        IPv6Interface: _family_strict(IPIface, IPv6Interface),
        IPv4Network: _family_strict(IPNet, IPv4Network),
        IPv6Network: _family_strict(IPNet, IPv6Network),
    }
)


def _resolve_parser(parser):
    """Map a result type to its factory, or pass a callable straight through.

    ``dict`` lookup on a ``Union`` alias works (they hash by their args), but
    an unhashable ``parser`` would raise, so the lookup is guarded.
    """
    try:
        resolved = _PARSER_FOR_TYPE.get(parser)
    except TypeError:  # unhashable -- definitely not one of our types
        resolved = None
    if resolved is not None:
        return resolved

    # A typing construct that is not in the map (an input-only ``*Like`` alias,
    # or any other Union) is a caller mistake. It must be rejected explicitly:
    # on Python 3.9 these objects *are* callable -- ``Union[...](x)`` reaches
    # ``_GenericAlias.__call__`` -- so a bare ``callable()`` test lets them
    # through and they fail later with a far more confusing error.
    if _typing_get_origin(parser) is not None:
        raise TypeError(
            "parser must be a result type or a callable, got the typing "
            "construct %r (input-only aliases like IPAddressLike describe what "
            "is accepted, not what to build)" % (parser,)
        )

    if not callable(parser):
        raise TypeError(
            "parser must be a callable or a netimps type, got %r" % (parser,)
        )
    return parser


#: Sentinel distinguishing "parser returned None" from "parser rejected the
#: input" -- ``None`` cannot do that job, since it is a legitimate result.
_MISSING = object()


def try_parse(
    value: object,
    parser: "Union[Type[_T], Callable[..., _T]]",
    default: "Any" = None,
) -> "Optional[_T]":
    """Return ``parser(value)``, or ``default`` if it rejects the input. Never raises.

    The one non-raising parse for the whole package. ``parser`` is either a
    **type** -- including the union aliases, which are not themselves callable
    -- or any callable that signals bad input with ``ValueError``/``TypeError``::

        try_parse("10.0.0.5", IPAddress)     # IPv4Address('10.0.0.5')
        try_parse("10.0.0.5", IPAddr)        # same, via the factory directly
        try_parse("nonsense", IPAddress)     # None
        try_parse(user_input, MACAddress) or DEFAULT_MAC
        try_parse(raw, IPAddress, default=LOCALHOST)   # explicit fallback

    The union aliases ``IPAddress``/``IPInterface``/``IPNetwork`` accept either
    family. A **concrete** type stays strict, so asking for one family and
    getting the other is impossible::

        try_parse("::1", IPAddress)      # IPv6Address('::1')  -- either family
        try_parse("::1", IPv4Address)    # None                -- v4 was asked for
        try_parse("10.0.0.5", IPv4Address)   # IPv4Address('10.0.0.5')

    Prefer this to ``is_valid`` followed by a parse: that pattern does the work
    twice and leaves a window where the two disagree.

    Generic in the parser: ``try_parse(x, MACAddress)`` is typed
    ``Optional[MACAddress]``, so a checker knows the result without a cast.

    Only ``ValueError`` and ``TypeError`` are swallowed -- the two exceptions
    that mean "bad input". Anything else (an ``OSError`` from a parser that
    touches the network, a bug in the parser) propagates, because turning it
    into ``None`` would disguise a real failure as a rejected value. A
    ``parser`` that is neither callable nor a known type raises ``TypeError``:
    that is a caller bug, not a rejected value.

    :param default: returned instead of ``None`` when the input is rejected.
        Also the seam :func:`is_valid` uses -- passing a sentinel is the only
        way to tell "parser returned ``None``" from "parser said no".
    """
    parser = _resolve_parser(parser)
    try:
        return parser(value)
    except (ValueError, TypeError):
        return default


def is_valid(
    value: object, parser: "Union[Type[_T], Callable[..., _T]]"
) -> "TypeGuard[_T]":
    """Return ``True`` if ``parser(value)`` succeeds. Never raises.

    The generic "can this be parsed?" check behind :func:`is_valid_ip` and
    :func:`is_valid_mac`. Accepts the same ``parser`` forms as
    :func:`try_parse` -- a type, a union alias, or any callable::

        is_valid("10.0.0.5", IPAddress)      # True  (the type alias)
        is_valid("10.0.0.0/24", IPNet)       # True  (the factory)
        is_valid("aa:bb:cc:dd:ee:ff", MACAddress)
        is_valid("nonsense", IPAddress)      # False

    Declared as a :data:`typing.TypeGuard`, so a checker **narrows the value**
    in the ``True`` branch::

        def handle(raw: object) -> None:
            if is_valid(raw, IPAddr):
                raw.is_private        # raw is IPv4Address | IPv6Address here

    When you want the parsed value too, use :func:`try_parse` instead of
    calling this first -- one call, no double work. Same exception policy: only
    ``ValueError``/``TypeError`` count as "invalid".

    .. note::
       A parser that legitimately returns ``None`` for valid input still counts
       as valid here -- the parse *succeeded*. That is why this delegates via a
       sentinel rather than testing ``try_parse(...) is not None``, which cannot
       tell "returned None" from "rejected the input".
    """
    return try_parse(value, parser, _MISSING) is not _MISSING


def is_valid_ip(value: object) -> "TypeGuard[IPAddress]":
    """Return ``True`` if ``value`` is a valid IPv4/IPv6 address.

    Never raises: any input that :func:`ipaddress.ip_address` rejects (including
    non-string types and empty strings) yields ``False``. Shorthand for
    ``is_valid(value, IPAddr)``.
    """
    return is_valid(value, _ipaddress.ip_address)


def is_valid_network(value: object) -> "TypeGuard[IPNetwork]":
    """Return ``True`` if ``value`` is a valid IPv4/IPv6 network. Never raises.

    Non-strict, matching :func:`IPNet`: ``"10.0.0.5/24"`` is valid and
    normalises to ``10.0.0.0/24``.
    """
    return is_valid(value, IPNet)


# ---------------------------------------------------------------------------
# MAC address
# ---------------------------------------------------------------------------


class MACAddress:
    """An IEEE 802 MAC address.

    Accepts the common textual forms on construction -- colon (``AA:BB:CC:DD:EE:FF``),
    hyphen (``AA-BB-CC-DD-EE-FF``), dot/Cisco (``aabb.ccdd.eeff``) or bare
    (``AABBCCDDEEFF``) -- as well as an ``int`` or another ``MACAddress``. The
    value is normalised to lowercase and compared/hashed by its canonical bytes,
    so instances are usable as dict keys and set members.

    ``as_str(sep)`` renders the address with an arbitrary separator between
    octets; ``sep=""`` produces the bare form.
    """

    #: Compiled pattern matching the accepted textual MAC forms. Exposed as a
    #: class attribute so callers can pre-screen text with
    #: ``MACAddress._VALID_MAC.match(text)`` before attempting construction.
    _VALID_MAC = _re.compile(
        r"^(?:"
        r"[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}"  # colon/hyphen separated
        r"|[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2}"  # dot / Cisco triplets
        r"|[0-9A-Fa-f]{12}"  # bare, no separators
        r")$"
    )

    __slots__ = ("_octets",)

    def __init__(self, value: MACLike) -> None:
        if isinstance(value, MACAddress):
            self._octets = value._octets
            return
        if isinstance(value, (bytes, bytearray)):
            octets = bytes(value)
            if len(octets) != 6:
                raise ValueError("MAC address must be 6 bytes, got %d" % len(octets))
            self._octets = octets
            return
        if isinstance(value, int):
            if value < 0 or value > 0xFFFFFFFFFFFF:
                raise ValueError("MAC integer out of range: %r" % (value,))
            self._octets = value.to_bytes(6, "big")
            return
        if isinstance(value, str):
            text = value.strip()
            if not self._VALID_MAC.match(text):
                raise ValueError("Invalid MAC address: %r" % (value,))
            hexdigits = _re.sub(r"[.:-]", "", text)
            self._octets = bytes.fromhex(hexdigits)
            return
        raise TypeError("Cannot build MACAddress from %r" % (type(value).__name__,))

    def as_str(self, sep: str = ":", upper: bool = False) -> str:
        """Return the MAC as a string with ``sep`` between octets.

        Lowercase by default (the canonical form used by ``str(mac)`` and by
        equality/hashing); pass ``upper=True`` for the uppercase rendering
        favoured by Windows tooling and much vendor output::

            mac.as_str("-")               # 'aa-bb-cc-dd-ee-ff'
            mac.as_str("-", upper=True)   # 'AA-BB-CC-DD-EE-FF'

        Case affects only this rendering -- two ``MACAddress`` values that
        differ solely in the case they were parsed from remain equal.
        """
        fmt = "%02X" if upper else "%02x"
        return sep.join(fmt % b for b in self._octets)

    @property
    def packed(self) -> bytes:
        """The 6 raw bytes of the address.

        The escape hatch for wire formats and syscalls, mirroring
        :attr:`ipaddress.IPv4Address.packed`. ``MACAddress`` deliberately is
        not a :class:`bytes` subclass -- see the class docstring.
        """
        return self._octets

    @property
    def oui(self) -> bytes:
        """The 3-byte Organisationally Unique Identifier (vendor prefix)."""
        return self._octets[:3]

    @property
    def is_multicast(self) -> bool:
        """True if the group bit (low bit of the first octet) is set.

        Multicast MACs are destinations only -- a NIC never *has* one -- so
        this is the check for "did I mistake a group address for a host?".
        """
        return bool(self._octets[0] & 0x01)

    @property
    def is_local(self) -> bool:
        """True if locally administered (the U/L bit is set).

        Locally administered addresses are assigned by software -- VMs,
        containers, and MAC-randomising clients -- rather than burned in by the
        vendor, so they are not stable identifiers.
        """
        return bool(self._octets[0] & 0x02)

    @property
    def is_universal(self) -> bool:
        """True if universally administered (vendor-assigned). Inverse of :attr:`is_local`."""
        return not self.is_local

    def __int__(self) -> int:
        return int.from_bytes(self._octets, "big")

    def __lt__(self, other: object):
        if isinstance(other, MACAddress):
            return self._octets < other._octets
        return NotImplemented

    def __le__(self, other: object):
        if isinstance(other, MACAddress):
            return self._octets <= other._octets
        return NotImplemented

    def __gt__(self, other: object):
        if isinstance(other, MACAddress):
            return self._octets > other._octets
        return NotImplemented

    def __ge__(self, other: object):
        if isinstance(other, MACAddress):
            return self._octets >= other._octets
        return NotImplemented

    def __str__(self) -> str:
        return self.as_str(":")

    def __repr__(self) -> str:
        return "MACAddress(%r)" % (self.as_str(":"),)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, MACAddress):
            return self._octets == other._octets
        if isinstance(other, str):
            try:
                return self._octets == MACAddress(other)._octets
            except (ValueError, TypeError):
                return NotImplemented
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._octets)


def is_valid_mac(value: object) -> "TypeGuard[MACAddress]":
    """Return ``True`` if ``value`` is a valid MAC address. Never raises.

    The MAC counterpart of :func:`is_valid_ip`: any input :class:`MACAddress`
    rejects -- including wrong types and empty strings -- yields ``False``.
    Shorthand for ``is_valid(value, MACAddress)``.
    """
    return is_valid(value, MACAddress)


# ---------------------------------------------------------------------------
# Address classification / resolution helpers
# ---------------------------------------------------------------------------


def get_ip(address: str) -> Optional[IPAddress]:
    """Resolve a hostname *or* literal address to an address object, or ``None``.

    Tries to parse ``address`` as a literal first and falls back to a DNS
    lookup, returning ``None`` if both fail::

        get_ip("10.0.0.5")        # IPv4Address('10.0.0.5')   -- no DNS traffic
        get_ip("example.com")     # IPv4Address('93.184.216.34')
        get_ip("nonexistent.")    # None

    .. note::
       The difference from ``try_parse(address, IPAddr)`` matters: that never
       touches the network, while this **may block on DNS**. Use ``try_parse``
       to validate user input; use ``get_ip`` when you genuinely want a name
       resolved.
    """
    try:
        try:
            return _ipaddress.ip_address(address)
        except ValueError:
            return _ipaddress.ip_address(_socket.gethostbyname(address))
    except (ValueError, OSError):
        return None


def is_link_scoped(ip: IPAddress) -> bool:
    """True if ``ip`` is confined to link scope or narrower.

    Covers loopback (``127/8``, ``::1`` -- host scope) and link-local
    (``169.254/16``, ``fe80::/10`` -- link scope), borrowing IPv6's scope
    vocabulary for both families::

        is_link_scoped(IPAddr("127.0.0.1"))     # True  -- host scope
        is_link_scoped(IPAddr("169.254.1.1"))   # True  -- link scope
        is_link_scoped(IPAddr("10.0.0.5"))      # False -- private, but global scope

    The shared practical property is that neither can usefully be routed off
    the local host or link, so proxying, forwarding or advertising such an
    address is always wrong. Keeping the definition in one place stops each
    caller from writing a subtly different version.

    .. note::
       This is **not** "is private". RFC 1918 ranges (``10/8``,
       ``192.168/16``) are globally *scoped* and routable within a site, so
       they return ``False`` -- use ``ip.is_private`` for that question.
    """
    return ip.is_loopback or ip.is_link_local


#: Conventional scheme -> port mappings, consulted before the system services
#: database. Seeded with the entries :func:`socket.getservbyname` gets wrong or
#: does not know (it has no entry for the socks variants at all). Mutable via
#: :func:`register_port`; not a frozen table, deliberately -- consumers keep
#: needing to add their own.
_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "ftp": 21,
    "ftps": 990,
    "ssh": 22,
    "sftp": 22,
    "telnet": 23,
    "smtp": 25,
    "dns": 53,
    "tftp": 69,
    "pop3": 110,
    "ntp": 123,
    "imap": 143,
    "ldap": 389,
    "smb": 445,
    "smtps": 465,
    "syslog": 514,
    "ldaps": 636,
    "imaps": 993,
    "pop3s": 995,
    "socks": 1080,
    "socks4": 1080,
    "socks5": 1080,
    "mysql": 3306,
    "rdp": 3389,
    "postgresql": 5432,
    "redis": 6379,
    "http-alt": 8080,
}

#: Reverse index, rebuilt by :func:`register_port`. The *first* scheme
#: registered for a port wins as its canonical name, so ``port_scheme(1080)``
#: is ``"socks"`` rather than whichever alias happens to be last.
_PORT_SCHEMES: "dict" = {}


def _reindex_ports() -> None:
    _PORT_SCHEMES.clear()
    for name, num in _DEFAULT_PORTS.items():
        _PORT_SCHEMES.setdefault(num, name)


_reindex_ports()


def register_port(scheme: str, port: int, canonical: bool = False) -> None:
    """Register (or override) a scheme's conventional port.

    The built-in table covers the common cases, but every consumer eventually
    has a protocol of its own::

        register_port("myproto", 9999)
        get_default_port("myproto")     # 9999
        port_scheme(9999)               # 'myproto'

    :param scheme: scheme name; matched case-insensitively.
    :param port: TCP/UDP port number, 0-65535.
    :param canonical: make ``scheme`` the name :func:`port_scheme` returns for
        ``port``, displacing any existing one. By default the first registration
        for a port keeps that slot, so adding an alias does not silently change
        what an existing port maps back to.

    Raises :class:`ValueError` on an out-of-range port or empty scheme.
    """
    if not scheme or not scheme.strip():
        raise ValueError("scheme must be a non-empty string")
    if not isinstance(port, int) or isinstance(port, bool):
        raise TypeError("port must be an int, got %r" % (type(port).__name__,))
    if not 0 <= port <= 65535:
        raise ValueError("port out of range: %r" % (port,))

    scheme = scheme.strip().lower()
    _DEFAULT_PORTS[scheme] = port
    if canonical or port not in _PORT_SCHEMES:
        _PORT_SCHEMES[port] = scheme


def get_default_port(scheme: str) -> Optional[int]:
    """Return the conventional port for a URL scheme, or ``None`` if unknown.

    Checks the built-in/registered table first, then falls back to the system
    services database via :func:`socket.getservbyname`::

        get_default_port("https")    # 443
        get_default_port("socks5")   # 1080  (absent from /etc/services)
        get_default_port("nope")     # None

    Case-insensitive. Extend the table with :func:`register_port`.
    """
    scheme = scheme.lower()
    if scheme in _DEFAULT_PORTS:
        return _DEFAULT_PORTS[scheme]
    try:
        return _socket.getservbyname(scheme)
    except OSError:
        return None


def port_scheme(port: int) -> Optional[str]:
    """Return the conventional scheme for a port, or ``None`` if unknown.

    The inverse of :func:`get_default_port`::

        port_scheme(443)     # 'https'
        port_scheme(1080)    # 'socks'   (canonical name, not an alias)
        port_scheme(9999)    # None

    Falls back to the system services database via
    :func:`socket.getservbyport`. Where several schemes share a port, the
    canonical one is returned -- see :func:`register_port`.
    """
    if port in _PORT_SCHEMES:
        return _PORT_SCHEMES[port]
    try:
        return _socket.getservbyport(port)
    except (OSError, OverflowError, TypeError):
        return None


# ---------------------------------------------------------------------------
# DNS / reachability
# ---------------------------------------------------------------------------


def resolve(
    query: str,
    rdtype: str = "a",
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
) -> List[str]:
    """Resolve ``query`` via DNS and return the answers as a list of strings.

    ::

        resolve("example.com")                    # ['93.184.216.34']
        resolve("example.com", "aaaa")
        resolve("example.com", "mx", ns="1.1.1.1")

    Contract: always a ``list`` of string records, and an **empty list** when
    the name does not resolve -- never ``None``. Callers can therefore write
    ``if result:`` and index ``result[0]`` safely.

    :param query: the name (or address, for reverse types) to look up.
    :param rdtype: DNS record type (``"a"``, ``"aaaa"``, ``"mx"`` ...). Second
        because it is the argument callers actually vary.
    :param ns: optional nameserver, or list of nameservers, to query instead of
        the system resolver.
    :param timeout: seconds to spend on the whole resolution, retries included
        (``None`` for dnspython's default). Bounds *total* time, not each query
        -- a list of unreachable nameservers cannot stretch past it.
    :param port: nameserver port, for resolvers not on 53.
    :param tcp: query over TCP instead of UDP. Useful for large responses that
        would otherwise be truncated.

    A genuine lookup failure (NXDOMAIN, no answer, timeout, all servers failed)
    yields ``[]``; a malformed query or unknown record type raises
    :class:`ValueError`, since that is a caller bug rather than a DNS result.

    Requires the ``dnspython`` package (installed with ``netimps``).
    """
    from dns import resolver as _resolver

    r = _resolver.Resolver(configure=not ns)
    if isinstance(ns, str):
        ns = [ns]
    if ns:
        r.nameservers = list(ns)
    if port != 53:
        r.port = port
    if timeout is not None:
        # `timeout` bounds a single query; `lifetime` bounds the whole
        # resolution including retries against every nameserver. Without the
        # lifetime, a list of dead servers blocks for far longer than asked.
        r.timeout = timeout
        r.lifetime = timeout

    # Looked up by name rather than referenced directly: LifetimeTimeout only
    # exists in dnspython >= 2.0, and the set has shifted between releases, so
    # a hard reference would break on older versions. Anything missing simply
    # drops out of the tuple.
    _lookup_failures = tuple(
        exc
        for exc in (
            getattr(_resolver, name, None)
            for name in (
                "NXDOMAIN",  # name definitively does not exist
                "NoAnswer",  # name exists, no record of this type
                "NoNameservers",  # every nameserver refused or failed
                "LifetimeTimeout",  # ran out of time
                "Timeout",
                "NoResolverConfiguration",  # no system resolver to use
            )
        )
        if isinstance(exc, type) and issubclass(exc, Exception)
    )

    try:
        answer = r.resolve(query, rdtype, tcp=tcp)
    except _lookup_failures:
        # A genuine "no result" -- the documented [] contract.
        return []
    except Exception as exc:
        # Everything else (malformed name, unknown rdtype) is a caller bug
        # rather than a lookup outcome. The old code swallowed these into [],
        # which turned a typo'd record type into a silent empty result.
        raise ValueError("invalid DNS query %r (%s): %s" % (query, rdtype, exc))
    return [str(record) for record in answer]


def ping(
    hostname: str,
    tries: int = 1,
    timeout: float = 1.0,
    ipv6: Optional[bool] = None,
) -> bool:
    """Return ``True`` if ``hostname`` answers an ICMP echo within ``tries`` attempts.

    Shells out to the platform ``ping`` binary, translating ``timeout`` into the
    right per-platform flags (Windows ``-n``/``-w`` in milliseconds; POSIX
    ``-c``/``-W`` in whole seconds), and returns on the first success::

        ping("10.0.0.1")                      # one attempt, 1s timeout
        ping("example.com", tries=3, timeout=2.5)
        ping("2001:db8::1", ipv6=True)        # force ping6 semantics

    :param tries: attempts before giving up. Values below 1 are treated as 1.
    :param timeout: seconds to wait per attempt. POSIX ``ping`` only accepts a
        whole number of seconds, so sub-second values are rounded **up** to 1 --
        never down to 0, which some implementations read as "wait forever".
    :param ipv6: force the IPv6 (``-6``) or IPv4 (``-4``) binary. ``None``
        (default) lets the system resolver decide.

    An empty ``hostname`` is ``False``. Never raises: a missing ``ping`` binary
    or a non-zero exit both yield ``False``.

    .. note::
       This measures whether *ICMP echo* is answered, which is not the same as
       whether a host is up -- plenty of hosts and most cloud firewalls drop
       echo requests while serving traffic normally. Prefer a TCP connect to
       the port you actually care about when you can.
    """
    if not hostname:
        return False

    tries = max(1, tries)
    if _os.name == "nt":
        # Windows takes milliseconds and counts with -n.
        options = ["-n", "1", "-w", str(max(1, int(timeout * 1000)))]
    else:
        # POSIX -W is whole seconds; round up so a sub-second timeout never
        # becomes 0 (read as "no timeout" by some implementations).
        options = ["-c", "1", "-W", str(max(1, int(_math.ceil(timeout)))), "-n"]

    if ipv6 is True:
        options.append("-6")
    elif ipv6 is False:
        options.append("-4")

    # A hard cap on the subprocess itself: -W bounds how long ping waits for a
    # reply, but not how long name resolution can hang beforehand.
    wall_timeout = max(timeout, 1.0) + 5.0

    for _ in range(tries):
        try:
            response = _run(
                ["ping", *options, hostname],
                capture_output=True,
                timeout=wall_timeout,
            )
        except (OSError, _SubprocessTimeout):
            # No ping binary, or it hung past the wall clock.
            return False
        if response.returncode == 0:
            return True
    return False


# Imported last: _ifaddrs builds MACAddress objects, so it must load after the
# class above exists.
from ._ifaddrs import Interface, get_interfaces  # noqa: E402
