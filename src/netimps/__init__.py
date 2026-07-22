"""netimps -- small, self-contained network utilities.

A thin, typed convenience layer over the standard library's :mod:`ipaddress`
plus a handful of host helpers (DNS lookup, ping, interface discovery). One
flat import surface; the only runtime dependency is ``dnspython``, used solely
inside :func:`resolve`.

::

    import netimps

    netimps.parse("10.0.0.5")                           # -> IPv4Address
    netimps.MACAddress("AA:BB:CC:DD:EE:FF").as_str("-")
    netimps.resolve("example.com", "aaaa")
    for iface in netimps.get_interfaces():
        print(iface.name, iface.mac, iface.ips)

Types and parsing
-----------------
``IPAddress``/``IPInterface``/``IPNetwork`` are the v4/v6 unions you annotate
with, reading the way :class:`ipaddress.IPv4Address` does::

    def get_route(dst: netimps.IPAddress, via: netimps.IPNetwork) -> None: ...

The same names are what you *parse into*, via one entry point::

    parse(value, IPNetwork)              # raises on bad input
    try_parse(value, IPNetwork)          # None instead
    is_valid(value, IPNetwork)           # bool, and narrows the type

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
import sys as _sys
from subprocess import TimeoutExpired as _SubprocessTimeout
from subprocess import run as _run
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    List,
    Optional,
    Type,
    TypeVar,
    Union,
    overload,
)
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
    # Parsing.
    "parse",
    "try_parse",
    "is_valid",
    "is_valid_ip",
    "is_valid_network",
    "is_valid_mac",
    "get_ip",
    "is_link_scoped",
    "collapse",
    "subtract",
    "normalize_host",
    "get_default_port",
    "port_scheme",
    "register_port",
    "resolve",
    "ping",
    "PingResult",
    "Interface",
    "get_interfaces",
    # Socket / route helpers.
    "get_source_ip",
    "free_port",
    "tcp_check",
    "wait_for_port",
    "get_route",
    "Route",
    "hop_count",
    "path_mtu",
    "HOST_DN",
]

__version__ = "0.2.0"

#: Fully-qualified (or short) name of the host running this process.
HOST_DN = _platform.node()

# ---------------------------------------------------------------------------
# Public type aliases
# ---------------------------------------------------------------------------
# The v4/v6 unions callers annotate with, matching how ``ipaddress.IPv4Address``
# and friends read. They double as the ``type`` argument to ``parse()``.

#: Either concrete address type: ``IPv4Address | IPv6Address``.
IPAddress = Union[IPv4Address, IPv6Address]

#: Either concrete interface type (address + prefix).
IPInterface = Union[IPv4Interface, IPv6Interface]

#: Either concrete network type.
IPNetwork = Union[IPv4Network, IPv6Network]

#: Anything ``parse(..., IPAddress)`` accepts.
IPAddressLike = Union[str, int, IPv4Address, IPv6Address]

#: Anything ``parse(..., IPNetwork)`` accepts.
IPNetworkLike = Union[str, int, IPv4Network, IPv6Network, IPv4Address, IPv6Address]

#: Anything :class:`MACAddress` accepts.
MACLike = Union[str, int, bytes, "MACAddress"]

# Internal aliases kept as runtime objects (not just annotations) so they read
# well in tracebacks; the public spellings above are what callers should use.
_AddressValue = Union[str, int, "_ipaddress._BaseAddress"]
_NetworkValue = Union[str, int, "_ipaddress._BaseNetwork", "_ipaddress._BaseAddress"]


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

_T = TypeVar("_T")

# How each supported result type is built from a raw value. The stdlib
# ``ip_*`` functions rather than the concrete constructors, so every entry
# accepts the full range of inputs (str / int / packed bytes / an existing
# object) and picks the right family automatically.
_BUILDERS = {
    IPAddress: _ipaddress.ip_address,
    IPInterface: _ipaddress.ip_interface,
    IPNetwork: _ipaddress.ip_network,
}

# Concrete types build via the same version-agnostic function, then assert the
# family: asking for IPv4Address and getting an IPv6Address back would defeat
# the request. Keyed to the union whose builder they share.
_CONCRETE = {
    IPv4Address: IPAddress,
    IPv6Address: IPAddress,
    IPv4Interface: IPInterface,
    IPv6Interface: IPInterface,
    IPv4Network: IPNetwork,
    IPv6Network: IPNetwork,
}

# ``ip_network`` is the one builder whose stdlib default we override: it is
# strict by default, which rejects "10.0.0.5/24" (host bits set). Non-strict is
# the useful behaviour and what callers nearly always mean; pass strict=True to
# get the stdlib's.
_BUILDER_DEFAULTS = {
    _ipaddress.ip_network: {"strict": False},
}


def _check_parser(type) -> None:
    """Raise TypeError unless ``type`` is something :func:`parse` can build with.

    Split out so :func:`try_parse` can validate before entering its
    ``except (ValueError, TypeError)`` block -- otherwise an unusable parser is
    indistinguishable from a rejected value, and a caller bug returns the
    default instead of raising.
    """
    try:
        if type in _CONCRETE or type in _BUILDERS:
            return
    except TypeError:  # unhashable
        pass

    # A typing construct we do not build (an input-only ``*Like`` alias, or any
    # other Union) is a caller mistake, and must be rejected up front: on Python
    # 3.9 these objects *are* ``callable()`` -- ``Union[...](x)`` reaches
    # ``_GenericAlias.__call__`` -- so the callable check below would let them
    # past, to fail later with a far more confusing error.
    if _typing_get_origin(type) is not None:
        raise TypeError(
            "type must be a result type or a callable, got the typing "
            "construct %r (input-only aliases like IPAddressLike describe "
            "what is accepted, not what to build)" % (type,)
        )
    if not callable(type):
        raise TypeError("type must be a result type or a callable, got %r" % (type,))


if TYPE_CHECKING:
    # The union aliases are not ``type`` objects, so they need their own
    # signatures; without these a checker infers ``Never`` for every call that
    # passes one. Runtime keeps the single permissive implementation below.
    @overload
    def parse(value: object, type: Type[_T], **kwargs: Any) -> _T: ...
    @overload
    def parse(value: object, type: Any = ..., **kwargs: Any) -> Any: ...

    @overload
    def try_parse(
        value: object, parser: Type[_T], default: None = ..., **kwargs: Any
    ) -> Optional[_T]: ...
    @overload
    def try_parse(
        value: object, parser: Any = ..., default: Any = ..., **kwargs: Any
    ) -> Any: ...


def parse(value: object, type: "Any" = IPAddress, **kwargs) -> "Any":
    """Build ``type`` from ``value``, raising on bad input.

    The single parsing entry point. ``type`` is a result type -- one of the
    :data:`IPAddress`/:data:`IPInterface`/:data:`IPNetwork` unions, a concrete
    ``IPv4Address`` &co, or any callable::

        parse("10.0.0.5")                        # IPv4Address  (the default)
        parse("10.0.0.5/24", IPInterface)        # IPv4Interface
        parse("10.0.0.5/24", IPNetwork)          # IPv4Network('10.0.0.0/24')
        parse("10.0.0.5/24", IPNetwork, strict=True)   # raises: host bits set
        parse("aa:bb:cc:dd:ee:ff", MACAddress)   # MACAddress

    Every type accepts the full range of stdlib inputs -- ``str``, ``int``,
    packed ``bytes``, or an existing object -- because the builders are the
    ``ipaddress.ip_*`` functions rather than the concrete constructors.

    A **union** accepts either family; a **concrete** type enforces its own, so
    ``parse("::1", IPv4Address)`` raises rather than quietly returning an
    ``IPv6Address``.

    Networks are parsed **non-strict** by default (unlike the stdlib), so a host
    address with a prefix normalises to its network instead of raising. Extra
    ``kwargs`` pass through to the underlying builder.

    Raises :class:`ValueError` on malformed input or a family mismatch, and
    :class:`TypeError` for an unusable ``type``. Use :func:`try_parse` for the
    non-raising form.
    """
    # Guarded: an unhashable ``type`` would make these lookups raise TypeError,
    # which try_parse would then swallow into `default` -- turning a caller bug
    # into a silent "invalid value". Fall through to the explicit checks below.
    try:
        wanted = _CONCRETE.get(type)
        builder = _BUILDERS.get(wanted if wanted is not None else type)
    except TypeError:
        wanted = builder = None

    if builder is None:
        _check_parser(type)  # raises for anything unusable
        return type(value, **kwargs)

    options = dict(_BUILDER_DEFAULTS.get(builder, ()))
    options.update(kwargs)
    result = builder(value, **options)

    if wanted is not None and not isinstance(result, type):
        raise ValueError("%r is not a %s" % (value, type.__name__))
    return result


#: Sentinel distinguishing "parser returned None" from "parser rejected the
#: input" -- ``None`` cannot do that job, since it is a legitimate result.
_MISSING = object()


def try_parse(
    value: object,
    parser: "Any" = IPAddress,
    default: "Any" = None,
    **kwargs,
) -> "Any":
    """Return ``parser(value)``, or ``default`` if it rejects the input. Never raises.

    The one non-raising parse for the whole package. ``parser`` is either a
    **type** -- including the union aliases, which are not themselves callable
    -- or any callable that signals bad input with ``ValueError``/``TypeError``::

        try_parse("10.0.0.5", IPAddress)     # IPv4Address('10.0.0.5')
        try_parse("10.0.0.5", IPv4Address)   # concrete: v6 input rejected
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
    # Validate the parser *before* the try, so the TypeError raised for an
    # unusable one is not swallowed as if the value had been rejected. Only the
    # parse itself is guarded.
    _check_parser(parser)
    try:
        return parse(value, parser, **kwargs)
    except (ValueError, TypeError):
        return default


def is_valid(
    value: object,
    parser: "Any" = IPAddress,
    **kwargs,
) -> "bool":
    """Return ``True`` if ``parser(value)`` succeeds. Never raises.

    The generic "can this be parsed?" check behind :func:`is_valid_ip` and
    :func:`is_valid_mac`. Accepts the same ``parser`` forms as
    :func:`try_parse` -- a type, a union alias, or any callable::

        is_valid("10.0.0.5", IPAddress)      # True  (the type alias)
        is_valid("10.0.0.0/24", IPNetwork)   # True
        is_valid("aa:bb:cc:dd:ee:ff", MACAddress)
        is_valid("nonsense", IPAddress)      # False

    Declared as a :data:`typing.TypeGuard`, so a checker **narrows the value**
    in the ``True`` branch::

        def handle(raw: object) -> None:
            if is_valid(raw, IPAddress):
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
    return try_parse(value, parser, _MISSING, **kwargs) is not _MISSING


def is_valid_ip(value: object) -> "TypeGuard[IPAddress]":
    """Return ``True`` if ``value`` is a valid IPv4/IPv6 address.

    Never raises: any input that :func:`ipaddress.ip_address` rejects (including
    non-string types and empty strings) yields ``False``. Shorthand for
    ``is_valid(value, IPAddress)``.
    """
    return is_valid(value, IPAddress)


def is_valid_network(value: object) -> "TypeGuard[IPNetwork]":
    """Return ``True`` if ``value`` is a valid IPv4/IPv6 network. Never raises.

    Non-strict, like :func:`parse`: ``"10.0.0.5/24"`` is valid and
    normalises to ``10.0.0.0/24``.
    """
    return is_valid(value, IPNetwork)


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
       The difference from ``try_parse(address)`` matters: that never
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


def collapse(networks) -> "List[IPNetwork]":
    """Merge an iterable of networks into the smallest equivalent list.

    Adjacent and overlapping networks are combined; the result is sorted and
    covers exactly the same addresses::

        collapse(["10.0.0.0/25", "10.0.0.128/25"])   # [IPv4Network('10.0.0.0/24')]
        collapse(["10.0.0.0/24", "10.0.0.8/29"])     # [IPv4Network('10.0.0.0/24')]

    Accepts anything :func:`parse` does, mixed v4 and v6 -- the families are
    collapsed independently and returned v4 first. Raises :class:`ValueError`
    on malformed input.
    """
    v4, v6 = [], []
    for item in networks:
        net = parse(item, IPNetwork)
        (v4 if net.version == 4 else v6).append(net)
    out = []
    for group in (v4, v6):
        if group:
            out.extend(_ipaddress.collapse_addresses(group))
    return out


def subtract(networks, remove) -> "List[IPNetwork]":
    """Return ``networks`` minus every address in ``remove``.

    The set difference :mod:`ipaddress` leaves out -- it ships
    ``collapse_addresses`` but nothing to punch holes::

        subtract(["10.0.0.0/24"], ["10.0.0.64/26"])
        # [IPv4Network('10.0.0.0/26'), IPv4Network('10.0.0.128/25')]

        subtract(["0.0.0.0/0"], ["10.0.0.0/8", "192.168.0.0/16"])  # public v4

    The result is collapsed, so it is the minimal set of networks covering
    what is left. Removing something absent is a no-op, and removing a
    superset yields ``[]``. Mixed families are handled independently: an IPv6
    exclusion never affects IPv4 output.
    """
    remaining = collapse(networks)
    for item in remove:
        excluded = parse(item, IPNetwork)
        next_round = []
        for net in remaining:
            if net.version != excluded.version:
                next_round.append(net)  # different family: untouched
                continue
            if not (
                net.subnet_of(excluded)
                or excluded.subnet_of(net)
                or net.overlaps(excluded)
            ):
                next_round.append(net)
                continue
            if net.subnet_of(excluded):
                continue  # fully removed
            next_round.extend(net.address_exclude(excluded))
        remaining = next_round
    return collapse(remaining)


def normalize_host(text: str, default_port: Optional[int] = None):
    """Split ``"host:port"`` into ``(host, port)``, handling IPv6 brackets.

    The parsing that looks trivial until IPv6 arrives, because a bare v6
    address is *full of colons*::

        normalize_host("example.com:8080")     # ('example.com', 8080)
        normalize_host("10.0.0.5")             # ('10.0.0.5', None)
        normalize_host("[::1]:8080")           # ('::1', 8080)
        normalize_host("::1")                  # ('::1', None)   -- not port 1
        normalize_host("example.com", 443)     # ('example.com', 443)

    The rule this implements: a bare IPv6 address must **not** be split on its
    last colon, and only a bracketed one may carry a port. ``"::1"`` is the
    address, never host ``"::"`` port ``1`` -- the mistake hand-rolled splitters
    almost always make.

    Brackets are stripped from the returned host, and a scope id is preserved
    (``"[fe80::1%eth0]:80"`` -> ``("fe80::1%eth0", 80)``). ``default_port`` is
    used when no port is present.

    Raises :class:`ValueError` on empty input, an unclosed bracket, or a port
    that is not an integer in 0-65535.
    """
    if not isinstance(text, str) or not text.strip():
        raise ValueError("host must be a non-empty string, got %r" % (text,))
    text = text.strip()

    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            raise ValueError("unclosed '[' in %r" % (text,))
        host = text[1:end]
        rest = text[end + 1 :]
        if not rest:
            port = default_port
        elif rest.startswith(":"):
            port = _parse_port(rest[1:], text)
        else:
            raise ValueError("unexpected %r after ']' in %r" % (rest, text))
    elif text.count(":") > 1:
        # More than one colon and no brackets: a bare IPv6 address. Splitting
        # here would turn "::1" into host "::" port 1.
        host, port = text, default_port
    elif ":" in text:
        host, _, raw_port = text.partition(":")
        port = _parse_port(raw_port, text)
    else:
        host, port = text, default_port

    if not host:
        raise ValueError("empty host in %r" % (text,))
    return host, port


def _parse_port(raw: str, original: str) -> int:
    try:
        port = int(raw)
    except (TypeError, ValueError):
        raise ValueError("invalid port %r in %r" % (raw, original))
    if not 0 <= port <= 65535:
        raise ValueError("port out of range in %r" % (original,))
    return port


def is_link_scoped(ip: IPAddress) -> bool:
    """True if ``ip`` is confined to link scope or narrower.

    Covers loopback (``127/8``, ``::1`` -- host scope) and link-local
    (``169.254/16``, ``fe80::/10`` -- link scope), borrowing IPv6's scope
    vocabulary for both families::

        is_link_scoped(parse("127.0.0.1"))      # True  -- host scope
        is_link_scoped(parse("169.254.1.1"))    # True  -- link scope
        is_link_scoped(parse("10.0.0.5"))       # False -- private, global scope

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


def _native_record(record):
    """Convert a dnspython record to a native Python value.

    Address records become :mod:`ipaddress` objects, so a caller can compare
    and do membership tests without re-parsing. Everything else stays a
    ``str``, with the trailing root dot stripped from names and the quotes
    stripped from TXT strings -- the forms callers actually want.
    """
    text = str(record)
    address = try_parse(text)
    if address is not None:
        return address
    if len(text) > 1 and text.startswith('"') and text.endswith('"'):
        return text[1:-1]  # TXT records arrive quoted
    if text.endswith(".") and not text.endswith(".."):
        return text[:-1]  # names are fully qualified with a root dot
    return text


def resolve(
    query: str,
    rdtype: str = "a",
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
) -> "List[Any]":
    """Resolve ``query`` via DNS and return the answers as a list of strings.

    ::

        resolve("example.com")                    # ['93.184.216.34']
        resolve("example.com", "aaaa")
        resolve("example.com", "mx", ns="1.1.1.1")

    Contract: always a ``list``, **empty** when the name does not resolve --
    never ``None``. Callers can therefore write ``if result:`` and index
    ``result[0]`` safely.

    Records come back as **native types**: address records (``A``/``AAAA``) are
    :class:`ipaddress` objects, everything else is a ``str``::

        resolve("example.com")[0].is_private     # an IPv4Address, not "1.2.3.4"
        resolve("example.com", "mx")             # ['10 mail.example.com']
        resolve("example.com", "txt")            # ['v=spf1 -all']  -- unquoted

    Names lose their trailing root dot and TXT strings lose their surrounding
    quotes, since neither is wanted in practice.

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
    return [_native_record(record) for record in answer]


def _source_argument(source, want_ipv6: bool = False) -> Optional[str]:
    """Coerce a source spec to the address string ``ping`` needs.

    Accepts an :class:`Interface`, an address object, or a string. Interfaces
    are reduced to an address because Windows ``-S`` will not take an adapter
    name; ``None`` means "nothing usable here", which the caller must treat as
    a failure rather than silently omitting the flag.
    """
    # A MAC identifies an adapter, so look up which one carries it. Unknown
    # MACs are None ("no such interface"), never a silent fallback.
    if isinstance(source, MACAddress) or (
        isinstance(source, str) and is_valid_mac(source)
    ):
        wanted = MACAddress(source)
        source = next(
            (iface for iface in get_interfaces() if iface.mac == wanted), None
        )
        if source is None:
            return None

    if isinstance(source, Interface):
        candidates = source.ipv6 if want_ipv6 else source.ipv4
        for entry in candidates:
            if not entry.ip.is_loopback:
                return str(entry.ip)
        # Fall back to a loopback address if that is genuinely all it has.
        return str(candidates[0].ip) if candidates else None

    text = str(source).strip()
    return text or None


class PingResult:
    """Outcome of a :func:`ping`, usable directly as a boolean.

    ``ping()`` has always answered "did it reply?", so this stays truthy on
    success and falsy on failure -- ``if ping(host):`` keeps working -- while
    carrying the details a caller would otherwise re-run ``ping`` to scrape.

    Attributes:
        ok: whether the destination replied.
        host: the destination as given.
        rtt_ms: round-trip time in milliseconds, or ``None`` if not reported.
            Sub-millisecond replies (``time<1ms``) are recorded as ``0.0``,
            which is falsy -- test ``is None`` rather than truthiness.
        ttl: TTL/hop-limit of the reply, or ``None``. Counts *down* from the
            sender's initial value, so a smaller number means more hops.
        source: address that answered, which on success is the destination.
        attempts: how many probes were sent before this outcome.
    """

    __slots__ = ("ok", "host", "rtt_ms", "ttl", "source", "attempts")

    def __init__(self, ok, host, rtt_ms=None, ttl=None, source=None, attempts=1):
        self.ok = ok
        self.host = host
        self.rtt_ms = rtt_ms
        self.ttl = ttl
        self.source = source
        self.attempts = attempts

    def __bool__(self) -> bool:
        return bool(self.ok)

    def __repr__(self) -> str:
        return "PingResult(ok=%r, host=%r, rtt_ms=%r, ttl=%r)" % (
            self.ok,
            self.host,
            self.rtt_ms,
            self.ttl,
        )

    def __eq__(self, other: object) -> bool:
        # Compares equal to a plain bool so existing `== True` assertions and
        # boolean-returning call sites keep behaving.
        if isinstance(other, bool):
            return bool(self) is other
        if isinstance(other, PingResult):
            return (
                self.ok == other.ok
                and self.host == other.host
                and self.rtt_ms == other.rtt_ms
                and self.ttl == other.ttl
            )
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.ok, self.host, self.rtt_ms, self.ttl))


#: ``time=5ms`` / ``time<1ms`` / ``time=0.043 ms`` across platforms.
_PING_RTT = _re.compile(r"time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms", _re.IGNORECASE)
#: ``TTL=119`` (Windows) / ``ttl=54`` (POSIX).
_PING_TTL = _re.compile(r"ttl[=\s]\s*([0-9]+)", _re.IGNORECASE)


def _parse_ping_output(text: str, expect):
    """Pull (rtt_ms, ttl, source) out of ping's stdout.

    Reads only numeric tokens that are stable across platforms and locales;
    the surrounding prose is never matched.
    """
    rtt = ttl = source = None
    for line in text.splitlines():
        lowered = line.lower()
        if "expired" in lowered or "unreachable" in lowered:
            continue
        found_rtt = _PING_RTT.search(line)
        found_ttl = _PING_TTL.search(line)
        if found_rtt is None and found_ttl is None:
            continue
        if found_rtt is not None and rtt is None:
            try:
                rtt = float(found_rtt.group(1))
            except ValueError:
                pass
        if found_ttl is not None and ttl is None:
            try:
                ttl = int(found_ttl.group(1))
            except ValueError:
                pass
        if source is None and expect is not None and str(expect) in line:
            source = expect
        break
    return rtt, ttl, source


def ping(
    hostname: str,
    tries: int = 1,
    timeout: float = 1.0,
    ipv6: Optional[bool] = None,
    source: Optional[str] = None,
    size: Optional[int] = None,
    ttl: Optional[int] = None,
    dont_fragment: bool = False,
) -> "PingResult":
    """Ping ``hostname``; the result is truthy if it answered.

    Returns a :class:`PingResult` rather than a bare bool, so the reply details
    are available without re-running and re-parsing ``ping``::

        if ping("8.8.8.8"):                  # still reads as a boolean
            ...
        result = ping("8.8.8.8")
        result.rtt_ms                        # 5.0
        result.ttl                           # 119

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
    :param source: send from this local address, choosing which interface the
        echo leaves by. Accepts an :class:`Interface`, an address object, or a
        string::

            ping("8.8.8.8", source=get_source_ip())            # address object
            ping("8.8.8.8", source=get_interfaces()[0])        # Interface
            ping("8.8.8.8", source="192.0.2.10")               # literal
            ping("8.8.8.8", source=MACAddress("00:00:5e:00:53:01"))  # by MAC

        A **MAC address** (object or string) is resolved to the interface
        holding it -- convenient when the adapter is known by hardware address
        rather than by a possibly-changing IP. An unknown MAC yields a falsy
        result rather than falling back.

        An ``Interface`` contributes its first non-loopback IPv4 address (its
        IPv6 address when ``ipv6=True``), because Windows ``-S`` requires an
        *address* -- passing an adapter name there fails. POSIX ``-I`` would
        accept a name, but resolving it here keeps behaviour identical on both.
        An interface holding no usable address yields a falsy result rather
        than falling back to the default route.

        Likewise an address not held by any local interface makes ``ping``
        fail, so the result is falsy -- this never silently reroutes.
    :param size: ICMP payload bytes (Windows ``-l``, POSIX ``-s``). The wire
        packet is 28 bytes larger (20 IP + 8 ICMP header), which matters when
        sizing against an MTU: payload 1472 is exactly 1500 on the wire.
    :param ttl: initial hop limit (``-i`` on Windows, ``-t`` on POSIX -- the
        letters are **swapped** between platforms, a classic source of scripts
        that silently do the wrong thing).

        A ``ttl`` too small to reach the target yields ``False`` on every
        platform. That takes explicit work on Windows, whose ``ping`` exits
        ``0`` for "TTL expired in transit" -- counting a router's error as a
        received reply -- so the raw exit code would report success although
        the target was never reached. The reply address is verified instead
        (see below), which is locale-independent.
    :param dont_fragment: set the DF bit (Windows ``-f``, Linux ``-M do``).
        Combined with ``size``, the standard manual MTU probe: the largest
        ``size`` that still succeeds is the path MTU minus 28. Unsupported on
        macOS/BSD ping, where it is ignored.

    An empty ``hostname`` gives a falsy result. Never raises: a missing ``ping``
    binary or a non-zero exit both yield a falsy :class:`PingResult`.

    .. note::
       This measures whether *ICMP echo* is answered, which is not the same as
       whether a host is up -- plenty of hosts and most cloud firewalls drop
       echo requests while serving traffic normally. Prefer a TCP connect to
       the port you actually care about when you can.
    """
    if not hostname:
        return PingResult(False, hostname, attempts=0)

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

    if source is not None:
        resolved_source = _source_argument(source, want_ipv6=bool(ipv6))
        if resolved_source is None:
            # An interface with no usable address cannot be a source.
            return PingResult(False, hostname, attempts=0)
        # Windows spells it -S <addr>; POSIX uses -I <addr-or-ifname>.
        options.extend(["-S" if _os.name == "nt" else "-I", resolved_source])

    if size is not None:
        if size < 0:
            raise ValueError("size must be non-negative, got %r" % (size,))
        options.extend(["-l" if _os.name == "nt" else "-s", str(size)])

    if ttl is not None:
        if not 1 <= ttl <= 255:
            raise ValueError("ttl must be 1-255, got %r" % (ttl,))
        # -i on Windows is TTL; on POSIX -i is the *interval* and -t is TTL.
        options.extend(["-i" if _os.name == "nt" else "-t", str(ttl)])

    if dont_fragment:
        if _os.name == "nt":
            options.append("-f")
        elif _sys.platform.startswith("linux"):
            options.extend(["-M", "do"])
        # macOS/BSD ping has no portable DF flag; silently omitted.

    # A hard cap on the subprocess itself: -W bounds how long ping waits for a
    # reply, but not how long name resolution can hang beforehand.
    wall_timeout = max(timeout, 1.0) + 5.0

    # Windows exits 0 for "TTL expired in transit", so a zero exit alone does
    # not mean the target answered. Confirm the reply came from the target
    # itself by matching its address in the output -- an address comparison,
    # never the localised prose around it.
    expect_address = try_parse(hostname)
    if expect_address is None:
        try:
            expect_address = try_parse(_socket.gethostbyname(hostname))
        except OSError:
            expect_address = None

    for attempt in range(1, tries + 1):
        try:
            response = _run(
                ["ping", *options, hostname],
                capture_output=True,
                timeout=wall_timeout,
            )
        except (OSError, _SubprocessTimeout):
            # No ping binary, or it hung past the wall clock.
            return PingResult(False, hostname, attempts=attempt)
        if response.returncode != 0:
            continue

        text = (response.stdout or b"").decode("utf-8", "replace")

        # A zero exit is not proof the *target* answered: Windows also exits 0
        # for "TTL expired in transit", where a router replied instead. Confirm
        # by address, which is locale-independent -- but only when the target's
        # address is known, since a bare exit code is all we have otherwise.
        if expect_address is not None:
            needle = "%s:" % expect_address
            answered = False
            for line in text.splitlines():
                if needle not in line:
                    continue
                lowered = line.lower()
                if "expired" in lowered or "unreachable" in lowered:
                    continue  # a router's error, not the destination
                if "bytes=" in lowered or "time" in lowered or "ttl=" in lowered:
                    answered = True
                    break
            if not answered:
                continue

        rtt, reply_ttl, source = _parse_ping_output(text, expect_address)
        return PingResult(
            True,
            hostname,
            rtt_ms=rtt,
            ttl=reply_ttl,
            source=source if source is not None else expect_address,
            attempts=attempt,
        )
    return PingResult(False, hostname, attempts=tries)


# Imported last: _ifaddrs builds MACAddress objects, so it must load after the
# class above exists.
from ._ifaddrs import Interface, get_interfaces  # noqa: E402
from ._sockets import (  # noqa: E402
    Route,
    free_port,
    get_source_ip,
    hop_count,
    path_mtu,
    get_route,
    tcp_check,
    wait_for_port,
)
