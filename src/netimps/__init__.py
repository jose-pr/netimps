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

import platform as _platform
from typing import (
    TYPE_CHECKING,
    Any,
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

from ._ip import (
    APIPA,
    LINK_LOCAL_V6,
    LOOPBACK_V4,
    LOOPBACK_V6,
    Host,
    _BUILDERS,
    _BUILDER_DEFAULTS,
    _CONCRETE,
    IPAddress,
    IPAddressLike,
    IPInterface,
    IPNetwork,
    IPNetworkLike,
    collapse,
    get_ip,
    is_link_scoped,
    normalize_host,
    subtract,
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
    "get_ip",
    "Host",
    "is_link_scoped",
    "APIPA",
    "LOOPBACK_V4",
    "LOOPBACK_V6",
    "LINK_LOCAL_V6",
    "collapse",
    "subtract",
    "normalize_host",
    "get_default_port",
    "get_default_scheme",
    "register_port",
    "resolve",
    "ping",
    "PingResult",
    "Interface",
    "get_interfaces",
    "iter_addresses",
    # Socket / route helpers.
    "get_source_ip",
    "free_port",
    "tcp_check",
    "wait_for_port",
    "get_route",
    "bind",
    "bind_error_hint",
    "interface_for",
    "UdpEndpoint",
    "Datagram",
    "retry",
    "backoff_delays",
    # Scanning.
    "scan_ports",
    "scan_hosts",
    "PORT_RANGES",
    # Multicast.
    "multicast_socket",
    "join_group",
    "leave_group",
    "is_multicast",
    "Route",
    "hop_count",
    "path_mtu",
    "HOST_DN",
]

__version__ = "0.3.0"

#: Fully-qualified (or short) name of the host running this process.
HOST_DN = _platform.node()

# ---------------------------------------------------------------------------
# Public type aliases
# ---------------------------------------------------------------------------
# The v4/v6 unions callers annotate with, matching how ``ipaddress.IPv4Address``
# and friends read. They double as the ``type`` argument to ``parse()``.

_T = TypeVar("_T")


def _check_parser(type) -> None:
    """Raise TypeError unless ``type`` is something :func:`parse` can build with.

    Split out so :func:`try_parse` can validate before entering its
    ``except (ValueError, TypeError)`` block -- otherwise an unusable type is
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
        value: object, type: Type[_T], default: None = ..., **kwargs: Any
    ) -> Optional[_T]: ...
    @overload
    def try_parse(
        value: object, type: Any = ..., default: Any = ..., **kwargs: Any
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


#: Sentinel distinguishing "the parse returned None" from "it rejected the
#: input" -- ``None`` cannot do that job, since it is a legitimate result.
_MISSING = object()


def try_parse(
    value: object,
    type: "Any" = IPAddress,
    default: "Any" = None,
    **kwargs,
) -> "Any":
    """Return ``type(value)``, or ``default`` if it rejects the input. Never raises.

    The one non-raising parse for the whole package. ``type`` is either a
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

    Generic in the type: ``try_parse(x, MACAddress)`` is typed
    ``Optional[MACAddress]``, so a checker knows the result without a cast.

    Only ``ValueError`` and ``TypeError`` are swallowed -- the two exceptions
    that mean "bad input". Anything else (an ``OSError`` from a builder that
    touches the network, a bug in it) propagates, because turning it
    into ``None`` would disguise a real failure as a rejected value. A
    ``type`` that is neither callable nor a known type raises ``TypeError``:
    that is a caller bug, not a rejected value.

    :param default: returned instead of ``None`` when the input is rejected.
        Also the seam :func:`is_valid` uses -- passing a sentinel is the only
        way to tell "the parse returned ``None``" from "it rejected the input".
    """
    # Validate the type *before* the try, so the TypeError raised for an
    # unusable one is not swallowed as if the value had been rejected. Only the
    # parse itself is guarded.
    _check_parser(type)
    try:
        return parse(value, type, **kwargs)
    except (ValueError, TypeError):
        return default


def is_valid(
    value: object,
    type: "Any" = IPAddress,
    **kwargs,
) -> "bool":
    """Return ``True`` if ``value`` parses as ``type``. Never raises.

    Accepts the same ``type`` forms as :func:`try_parse` -- a type, a union
    alias, or any callable::

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
    return try_parse(value, type, _MISSING, **kwargs) is not _MISSING


# ---------------------------------------------------------------------------
# Address classification / resolution helpers
# ---------------------------------------------------------------------------


# Imported last, and deliberately so: these submodules call back into this one
# (parse, try_parse, is_valid), so they must load after the definitions above.
# The names below are the public spellings -- the _-prefixed modules are
# implementation detail and must not be imported from outside the package.
from ._mac import MACAddress, MACLike  # noqa: E402
from ._scheme import (  # noqa: E402
    get_default_port,
    get_default_scheme,
    register_port,
)
from ._ifaddrs import Interface, get_interfaces, iter_addresses  # noqa: E402
from ._dns import resolve  # noqa: E402
from ._ping import PingResult, ping  # noqa: E402
from ._scan import PORT_RANGES, scan_hosts, scan_ports  # noqa: E402
from ._multicast import (  # noqa: E402
    is_multicast,
    join_group,
    leave_group,
    multicast_socket,
)
from ._retry import backoff_delays, retry  # noqa: E402
from ._udp import Datagram, UdpEndpoint  # noqa: E402
from ._sockets import (  # noqa: E402
    bind,
    bind_error_hint,
    interface_for,
    Route,
    free_port,
    get_source_ip,
    hop_count,
    path_mtu,
    get_route,
    tcp_check,
    wait_for_port,
)
