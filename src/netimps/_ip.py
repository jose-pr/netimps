"""IP address, interface and network types (internal).

The v4/v6 union aliases callers annotate with, the builder tables :func:`parse`
dispatches on, and the address/network helpers that are specific to IP (as
opposed to the generic parsing combinators, which live in ``_parse``).

Re-exported from :mod:`netimps`.
"""

from __future__ import annotations

import ipaddress as _ipaddress
import platform as _platform
import socket as _socket
from typing import (
    Any,
    Iterable,
    List,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
)

from ._exceptions import NetimpsValueError, ResolutionError

# `_fqdn` imports nothing from this module at import time (it reaches for
# `IPAddress` inside the one function that needs it), which is what lets
# `HostLike` below name the class itself.
from ._fqdn import FQDN
from ._scheme import coerce_port

from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)

_D = TypeVar("_D")
_H = TypeVar("_H", bound="Host")

__all__ = [
    "Host",
    "LINK_LOCAL_V4",
    "LOOPBACK_V4",
    "LOOPBACK_V6",
    "LINK_LOCAL_V6",
    "IPAddress",
    "IPInterface",
    "IPNetwork",
    "IPAddressLike",
    "IPInterfaceLike",
    "IPNetworkLike",
    "HostLike",
    "IPv4Address",
    "IPv4Interface",
    "IPv4Network",
    "IPv6Address",
    "IPv6Interface",
    "IPv6Network",
    "get_hostname",
    "collapse",
    "subtract",
    "split_host",
    "split_zone",
    "join_host",
    "unmap",
    "is_wildcard",
    "is_link_scoped",
]

#: Either concrete address type: ``IPv4Address | IPv6Address``.
IPAddress = Union[IPv4Address, IPv6Address]

#: Either concrete interface type (address + prefix).
IPInterface = Union[IPv4Interface, IPv6Interface]

#: Either concrete network type.
IPNetwork = Union[IPv4Network, IPv6Network]

#: Anything ``parse(..., IPAddress)`` accepts.
IPAddressLike = Union[str, int, bytes, IPv4Address, IPv6Address]

#: Anything ``parse(..., IPInterface)`` accepts.
IPInterfaceLike = Union[
    str,
    int,
    bytes,
    IPv4Address,
    IPv6Address,
    IPv4Interface,
    IPv6Interface,
    IPv4Network,
    IPv6Network,
    Tuple[
        Union[str, int, bytes, IPv4Address, IPv6Address],
        Union[str, int],
    ],
]

#: Anything ``parse(..., IPNetwork)`` accepts.
IPNetworkLike = Union[
    str,
    int,
    bytes,
    IPv4Network,
    IPv6Network,
    IPv4Address,
    IPv6Address,
    IPv4Interface,
    IPv6Interface,
    Tuple[
        Union[str, int, bytes, IPv4Address, IPv6Address],
        Union[str, int],
    ],
]


# Internal aliases kept as runtime objects (not just annotations) so they read
# well in tracebacks; the public spellings above are what callers should use.
_AddressValue = Union[str, int, bytes, "_ipaddress._BaseAddress"]
_NetworkValue = Union[
    str,
    int,
    bytes,
    "_ipaddress._BaseNetwork",
    "_ipaddress._BaseAddress",
]


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


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


def _dst_argument(value) -> str:
    """Coerce a destination-like value to the plain string a socket or
    subprocess call expects.

    An :class:`IPv4Interface`/:class:`IPv6Interface` unwraps to its
    ``.ip`` -- the ``/prefix`` means nothing to ``ping``/``getaddrinfo``, and
    stringifying the interface directly would pass ``"10.0.0.5/24"`` as the
    destination, which every caller of this (a subprocess argument, a
    socket call, a DNS query) reads as garbage rather than an address.

    An :class:`IPv4Network`/:class:`IPv6Network` has no single address, so it
    raises :class:`TypeError` rather than silently picking one (the network
    address? the first host address?) -- a caller who meant a specific
    address should say so.

    A string, an :class:`IPv4Address`/:class:`IPv6Address`, a :class:`Host` and
    an :class:`FQDN` stand for the text they hold. **Anything else raises
    :class:`TypeError`**, through the same allowlist as :func:`split_host`: a
    ``str()`` fallback read ``None`` as the host named ``"None"``, an answer
    that looks right and is not.
    """
    if isinstance(value, (IPv4Network, IPv6Network)):
        raise TypeError(
            "expected a single destination, not a network (%r) -- "
            "pass an address from it instead" % (value,)
        )
    if isinstance(value, (IPv4Interface, IPv6Interface)):
        return str(value.ip)
    if isinstance(value, (IPv4Address, IPv6Address)):
        return str(value)
    return _host_text(value)


def collapse(networks: "Iterable[IPNetworkLike]") -> "List[IPNetwork]":
    """Merge an iterable of networks into the smallest equivalent list.

    Adjacent and overlapping networks are combined; the result is sorted and
    covers exactly the same addresses::

        collapse(["10.0.0.0/25", "10.0.0.128/25"])   # [IPv4Network('10.0.0.0/24')]
        collapse(["10.0.0.0/24", "10.0.0.8/29"])     # [IPv4Network('10.0.0.0/24')]

    Accepts anything :func:`parse` does, mixed v4 and v6 -- the families are
    collapsed independently and returned v4 first. Raises :class:`ValueError`
    on malformed input.
    """
    from ._parse import parse as _parse

    v4: "List[IPv4Network]" = []
    v6: "List[IPv6Network]" = []
    for item in networks:
        net = _parse(item, IPNetwork)
        if isinstance(net, IPv4Network):
            v4.append(net)
        else:
            v6.append(net)
    out: "List[IPNetwork]" = []
    if v4:
        out.extend(_ipaddress.collapse_addresses(v4))
    if v6:
        out.extend(_ipaddress.collapse_addresses(v6))
    return out


def subtract(
    networks: "Iterable[IPNetworkLike]", remove: "Iterable[IPNetworkLike]"
) -> "List[IPNetwork]":
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
    from ._parse import parse as _parse

    remaining = collapse(networks)
    for item in remove:
        excluded = _parse(item, IPNetwork)
        next_round: "List[IPNetwork]" = []
        for net in remaining:
            if net.version != excluded.version:
                next_round.append(net)  # different family: untouched
                continue
            # mypy cannot see that the `.version` check above guarantees `net`
            # and `excluded` share a concrete type -- ipaddress's own stubs
            # type subnet_of/address_exclude as same-family-only, stricter
            # than the runtime, which accepts the IPv4Network|IPv6Network
            # union fine once the families actually match.
            if not (
                net.subnet_of(excluded)  # type: ignore[arg-type]
                or excluded.subnet_of(net)  # type: ignore[arg-type]
                or net.overlaps(excluded)
            ):
                next_round.append(net)
                continue
            if net.subnet_of(excluded):  # type: ignore[arg-type]
                continue  # fully removed
            next_round.extend(net.address_exclude(excluded))  # type: ignore[arg-type]
        remaining = next_round
    return collapse(remaining)


def _host_text(text: object) -> str:
    """The string a loose host value stands for.

    :raises TypeError: for a network (it names no single host) and for a value
        that is not a host type at all.
    """
    if isinstance(text, str):
        return text
    if isinstance(text, (IPv4Network, IPv6Network)):
        _dst_argument(text)  # raises TypeError, with the reason
    if isinstance(text, (IPv4Address, IPv6Address, IPv4Interface, IPv6Interface)):
        return _dst_argument(text)
    if isinstance(text, (Host, FQDN)):
        # Both stringify to the text the caller means -- `Host` to its
        # original spelling, `FQDN` to the name with its trailing dot if it
        # has one.
        return str(text)
    # An **allowlist**, not a `str()` fallback: a fallback turns `None` into
    # the hostname "None", a plausible answer that is wrong and that a caller
    # cannot detect.
    raise TypeError(
        "host must be a string, an address, a Host or an FQDN, not %r"
        % (type(text).__name__,)
    )


def split_zone(text: "HostLike") -> "Tuple[str, Optional[str]]":
    """Split an IPv6 ``%zone`` suffix off a host: ``(host, zone)``.

    ::

        split_zone("fe80::1%eth0")   # ('fe80::1', 'eth0')
        split_zone("fe80::1%12")     # ('fe80::1', '12')
        split_zone("10.0.0.5")       # ('10.0.0.5', None)
        split_zone("example.com")    # ('example.com', None)

    Use it before :func:`try_parse` or an address comparison: ``ipaddress`` keeps
    the zone as part of the address, so ``fe80::1%eth0`` is not equal to
    ``fe80::1`` and matches nothing in :func:`get_interfaces`. The zone names an
    *interface*, which is why it is returned rather than thrown away. Brackets are
    :func:`split_host`'s business, not this function's.

    ``text`` takes the package's loose host union. Raises :class:`TypeError`
    for a value that is not a host type, and :class:`NetimpsValueError` for a
    ``%`` with nothing after it.
    """
    value = _host_text(text)
    host, sep, zone = value.partition("%")
    if not sep:
        return value, None
    if not zone:
        raise NetimpsValueError("empty zone after '%%' in %r" % (value,))
    return host, zone


def split_host(
    text: "Union[HostLike, Tuple[HostLike, Optional[int]]]",
    *,
    default_port: Optional[int] = None,
) -> "Tuple[str, Optional[int]]":
    """Split ``"host:port"`` into ``(host, port)``, handling IPv6 brackets.

    The parsing that looks trivial until IPv6 arrives, because a bare v6
    address is *full of colons*::

        split_host("example.com:8080")     # ('example.com', 8080)
        split_host("10.0.0.5")             # ('10.0.0.5', None)
        split_host("[::1]:8080")           # ('::1', 8080)
        split_host("::1")                  # ('::1', None)   -- not port 1
        split_host("example.com", 443)     # ('example.com', 443)

    The rule this implements: a bare IPv6 address must **not** be split on its
    last colon, and only a bracketed one may carry a port. ``"::1"`` is the
    address, never host ``"::"`` port ``1`` -- the mistake hand-rolled splitters
    almost always make.

    Brackets are stripped from the returned host, and a scope id is preserved
    (``"[fe80::1%eth0]:80"`` -> ``("fe80::1%eth0", 80)``). A bracketed literal
    with no port is the host alone: ``"[::1]"`` is ``("::1", None)``.
    ``default_port`` is used when no port is present.

    A ``(host, port)`` **pair** is taken too, with ``port`` an integer or
    ``None`` and ``default_port`` filling a ``None``::

        split_host(("example.com", None), default_port=69)   # ('example.com', 69)
        split_host(("[::1]", 80))                            # ('::1', 80)

    The host of a pair is split like any other, so a port written in both places
    is an error unless they agree.

    ``text`` accepts the package's usual loose union, not only a ``str``: an
    address object, an :class:`IPv4Interface`/:class:`IPv6Interface` (its ``.ip``
    is used), a :class:`Host` or an :class:`FQDN`, as :func:`join_host`, the
    inverse, does. A *network*, or a value that is not a host type at all
    (``None``, an ``int``, ``bytes``), raises :class:`TypeError`.

    Port text is ASCII digits, as RFC 3986 section 3.2.3 has it: ``"8_0"``,
    ``"+80"``, a space and non-ASCII digits are refused. What sits inside
    brackets has to be an IPv6 literal (section 3.2.2).

    Raises :class:`NetimpsValueError` on empty input, an unclosed bracket,
    brackets around anything but an IPv6 address, a port that is not ASCII digits
    in 0-65535, or an unbracketed string with two or more colons that is **not**
    a valid IPv6 address (``"host:80:extra"``, a half-typed address).
    """
    if isinstance(text, tuple):
        return _split_pair(text, default_port)
    text = _host_text(text)
    if not text.strip():
        raise NetimpsValueError("host must be a non-empty string, got %r" % (text,))
    text = text.strip()

    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            raise NetimpsValueError("unclosed '[' in %r" % (text,))
        host = text[1:end]
        if not _is_ipv6_literal(host):
            raise NetimpsValueError(
                "%r is bracketed but not an IPv6 address" % (text[: end + 1],)
            )
        rest = text[end + 1 :]
        if not rest:
            port = default_port
        elif rest.startswith(":"):
            port = _parse_port(rest[1:], text)
        else:
            raise NetimpsValueError("unexpected %r after ']' in %r" % (rest, text))
    elif text.count(":") > 1:
        # More than one colon and no brackets: a bare IPv6 address is the only
        # thing that can be, and splitting would turn "::1" into host "::"
        # port 1. Confirm it really parses rather than assuming: taking the
        # whole unparseable string as the host is a confident wrong answer the
        # caller cannot detect.
        if not _is_ipv6_literal(text):
            raise NetimpsValueError(
                "%r has several colons but is not an IPv6 address; "
                "bracket it as [host]:port if a port was meant" % (text,)
            )
        host, port = text, default_port
    elif ":" in text:
        host, _, raw_port = text.partition(":")
        port = _parse_port(raw_port, text)
    else:
        host, port = text, default_port

    if not host:
        raise NetimpsValueError("empty host in %r" % (text,))
    return host, port


def _split_pair(pair: "Tuple[Any, ...]", default_port: Optional[int]):
    """``split_host`` for a ``(host, port)`` pair."""
    if len(pair) != 2:
        raise NetimpsValueError(
            "a (host, port) pair has two items, got %d: %r" % (len(pair), pair)
        )
    raw_host, raw_port = pair
    host, inner = split_host(raw_host)
    if raw_port is None:
        return host, inner if inner is not None else default_port
    if isinstance(raw_port, str):
        port = _parse_port(raw_port, pair)
    else:
        port = _port_number(raw_port, pair)
    if inner is not None and inner != port:
        raise NetimpsValueError(
            "two ports for one host: %r in the host and %d beside it" % (inner, port)
        )
    return host, port


def _is_ipv6_literal(text: str) -> bool:
    """True if ``text`` is an IPv6 address, zone id and all.

    ``IPv6Address`` accepts a ``%zone`` suffix from Python 3.9 on, which is the
    floor here, so the scoped form needs no special casing.
    """
    try:
        IPv6Address(text)
    except ValueError:
        return False
    return True


def _port_number(port: object, original: object) -> int:
    """``port`` through :func:`netimps._scheme.coerce_port`, the one place a port
    is validated, with a range error as the package's value error."""
    try:
        return coerce_port(port)
    except TypeError:
        raise
    except ValueError as exc:
        raise NetimpsValueError("%s, in %r" % (exc, original)) from None


def _parse_port(raw: str, original: object) -> int:
    """Port text: ASCII digits only (RFC 3986 ``port = *DIGIT``), then the gate."""
    if not (raw.isascii() and raw.isdigit()):
        raise NetimpsValueError("invalid port %r in %r" % (raw, original))
    return _port_number(int(raw), original)


def _family_argument(family: object, *, required: bool = False) -> "Optional[int]":
    """``socket.AF_INET`` or ``socket.AF_INET6`` for a family spelled either way.

    A family is ``4`` or ``6``, or the platform's ``AF_INET``/``AF_INET6``
    (``AF_INET6`` is 10 on Linux, 23 on Windows and 30 on macOS, so it is never
    compared against a literal). ``None`` means "either" unless ``required``.

    :raises ValueError: for anything else, a ``bool`` and a misspelt family
        included, rather than answering about a family nobody asked for.
    """
    if family is None and not required:
        return None
    if isinstance(family, int) and not isinstance(family, bool):
        if family in (4, _socket.AF_INET):
            return _socket.AF_INET
        if family in (6, _socket.AF_INET6):
            return _socket.AF_INET6
    raise ValueError(
        "family must be 4, 6, socket.AF_INET or socket.AF_INET6%s, got %r"
        % ("" if required else " (or None)", family)
    )


def _required_family(family: object) -> int:
    """:func:`_family_argument` where ``None`` is not an answer."""
    resolved = _family_argument(family, required=True)
    assert resolved is not None
    return resolved


def _as_address(value: object) -> "IPAddress":
    """The address ``value`` stands for, for the classifiers.

    Takes what :data:`IPAddressLike` does, and an interface (its ``.ip``), a
    :class:`Host` or an :class:`FQDN` holding address text.

    :raises TypeError: for a network, or a value of any other type.
    :raises NetimpsValueError: for text that is no address.
    """
    from ._parse import parse

    # An interface first: ``IPv4Interface`` subclasses ``IPv4Address``, and
    # returned as such it would compare as address *and* network.
    if isinstance(value, (IPv4Interface, IPv6Interface)):
        return value.ip
    if isinstance(value, (IPv4Address, IPv6Address)):
        return value
    if isinstance(value, (IPv4Network, IPv6Network)):
        raise TypeError("expected an address, not a network (%r)" % (value,))
    if isinstance(value, (Host, FQDN)):
        value = str(value)
    if isinstance(value, bool) or not isinstance(value, (str, int, bytes)):
        raise TypeError(
            "expected an address (text, int, bytes or an address object), not %r"
            % (type(value).__name__,)
        )
    return parse(value, IPAddress)


def is_link_scoped(ip: "IPAddressLike") -> bool:
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
    address = unmap(_as_address(ip))
    return address.is_loopback or address.is_link_local


# ---------------------------------------------------------------------------
# Well-known networks
# ---------------------------------------------------------------------------
# Named so callers read as the RFC does, instead of repeating literals. These
# are the ranges callers otherwise spell out by hand.

#: RFC 3927 link-local ("Automatic Private IP Addressing") -- what a host gives
#: itself when DHCP fails, so its presence usually means "no lease".
LINK_LOCAL_V4 = IPv4Network("169.254.0.0/16")

#: RFC 1122 loopback. Note this is the whole /8, not just 127.0.0.1.
LOOPBACK_V4 = IPv4Network("127.0.0.0/8")

#: The single IPv6 loopback address, as a network for symmetry.
LOOPBACK_V6 = IPv6Network("::1/128")

#: RFC 4291 IPv6 link-local.
LINK_LOCAL_V6 = IPv6Network("fe80::/10")


class Host:
    """A host named by either an address or a hostname.

    Config files and URLs hold "the host" as a string that may be either, and
    the useful operations differ. This keeps the original text and resolves on
    demand::

        host = Host("db.internal")
        host.ip()                  # IPv4Address(...) once DNS answers
        str(host)                  # 'db.internal' -- always the original

        Host("10.0.0.5").is_address    # True, no DNS involved

    The point is that ``str(host)`` is **always what was given**, so a URL can
    still be rebuilt when resolution fails -- the case a bare lookup handles
    badly, since it returns ``None`` and loses the name.
    """

    __slots__ = ("value", "_resolved", "_attempted")

    value: str
    _resolved: "Optional[IPAddress]"
    _attempted: bool

    def __init__(self, value: "Optional[HostLike]") -> None:
        if isinstance(value, Host):
            value = value.value
        elif value is not None:
            # An interface is its address and a network is no host, as for
            # every `dst` parameter.
            value = _dst_argument(value)
        object.__setattr__(self, "value", "" if value is None else str(value).strip())
        object.__setattr__(self, "_resolved", None)
        object.__setattr__(self, "_attempted", False)

    def __reduce__(self) -> "Tuple[Any, Tuple[str]]":
        """Pickle and copy through the constructor; the memo is not carried.

        ``__slots__`` plus a blocked ``__setattr__`` defeats the default
        restore, which assigns the slots back onto a blank instance.
        """
        return (type(self), (self.value,))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Host is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Host is immutable")

    @classmethod
    def parse(cls: "Type[_H]", text: str) -> "_H":
        """Build a ``Host`` from text naming an address or a hostname.

        A ``Host`` keeps what it was given, so no spelling is rejected for its
        form; text with nothing in it is, since there is no host to name.
        The constructor is the lenient entry that takes ``None`` and ``""``.

        :raises NetimpsValueError: for empty or blank text. It is a
            ``ValueError``.
        :raises TypeError: for anything that is not ``str``.
        """
        if not isinstance(text, str):
            raise TypeError("Host.parse takes text, not %r" % (type(text).__name__,))
        if not text.strip():
            raise NetimpsValueError("a host cannot be empty")
        return cls(text)

    @overload
    @classmethod
    def try_parse(cls: "Type[_H]", text: str) -> "Optional[_H]": ...

    @overload
    @classmethod
    def try_parse(cls: "Type[_H]", text: str, default: _D) -> "Union[_H, _D]": ...

    @classmethod
    def try_parse(cls, text: str, default: Any = None) -> Any:
        """Return ``parse(text)``, or ``default`` for empty or blank text.

        :raises TypeError: for anything that is not ``str``; only bad *text*
            is answered with ``default``. :func:`netimps.try_parse` is the
            entry that answers ``default`` for any object.
        """
        if not isinstance(text, str):
            raise TypeError(
                "Host.try_parse takes text, not %r" % (type(text).__name__,)
            )
        if not text.strip():
            return default
        return cls(text)

    @property
    def is_address(self) -> bool:
        """True if the value is already an IP literal -- no DNS needed."""
        from ._parse import is_valid

        return is_valid(self.value, IPAddress)

    def fqdn(
        self,
        *,
        check: bool = False,
        ns: "Optional[Union[str, List[str]]]" = None,
        timeout: "Optional[float]" = 5.0,
        port: int = 53,
        tcp: bool = False,
        search: "Union[bool, List[str]]" = True,
        backends: "Optional[Union[str, List[str]]]" = None,
        source: "Optional[Union[str, List[str]]]" = None,
        cache: "Union[bool, float]" = False,
        deadline: "Optional[float]" = None,
    ) -> "Optional[FQDN]":
        """This host as an :class:`FQDN`: the name itself, or the name an address
        reverses to.

        **A name is returned as written, with no lookup**; an address costs a
        reverse (PTR) lookup, which can block::

            Host("www.example.com").fqdn().domain   # FQDN('example.com'), no I/O
            Host("10.0.0.5").fqdn()                 # FQDN('db.internal'), or None

        The bridge between the two types: :class:`Host` is "an address *or* a
        name", while :class:`FQDN` is a name algebra that refuses an address.
        The name is the one written, **not** the canonical name after
        search-list expansion, and a reverse answer comes back without its root
        dot.

        ``None`` is the answer when nothing was found, and also for text that is
        not a syntactically possible name (over-long, an empty inner label).
        With ``check=True`` the first raises :class:`ResolutionError` and the
        second :class:`NetimpsValueError`.

        The resolver options mean what they do for :meth:`ip`. There is no
        ``ipv6``: the address decides which reverse zone is asked. Nothing is
        memoised.
        """
        text = self.value
        if self.is_address:
            from ._dns import lookup_fqdn

            return lookup_fqdn(
                text,
                check=check,
                ns=ns,
                timeout=timeout,
                port=port,
                tcp=tcp,
                search=search,
                backends=backends,
                source=source,
                cache=cache,
                deadline=deadline,
            )
        return FQDN.parse(text) if check else FQDN.try_parse(text)

    def ip(
        self,
        *,
        check: bool = False,
        ipv6: "Optional[bool]" = None,
        ns: "Optional[Union[str, List[str]]]" = None,
        timeout: "Optional[float]" = 5.0,
        port: int = 53,
        tcp: bool = False,
        search: "Union[bool, List[str]]" = True,
        backends: "Optional[Union[str, List[str]]]" = None,
        source: "Optional[Union[str, List[str]]]" = None,
        cache: "Union[bool, float]" = False,
        deadline: "Optional[float]" = None,
        refresh: bool = False,
    ) -> "Optional[IPAddress]":
        """Resolve to an address, or ``None``.

        **A literal is returned as parsed, with no lookup**; a name is looked
        up, which can block.

        :param check: raise :class:`ResolutionError` instead of returning
            ``None`` when nothing was found -- an empty answer, an outage, or an
            empty host.
        :param ipv6: ``True`` asks for AAAA, ``False`` for A, ``None`` for either
            in one lookup, in the order the OS chose.
        :param ns: nameserver(s) to ask instead of the OS's.
        :param timeout: seconds per backend attempt; what it bounds differs by
            backend, see :func:`netimps.resolve`.
        :param deadline: seconds for the whole lookup, every backend and
            candidate included; ``None`` sets no overall limit.
        :param port: nameserver port.
        :param tcp: query over TCP.
        :param search: expand an unqualified name through a search list: the
            system's (``True``), none (``False``) or the list given.
        :param backends: which of ``"dnspython"``, ``"wire"``, ``"system"``,
            ``"nslookup"``, and in what order; see :func:`netimps.resolve`.
        :param source: the local address the query is sent from.
        :param cache: reuse a recent answer, a miss included, from the shared
            resolution cache: ``False`` (the default) never reads or writes it,
            ``True`` keeps an answer for :data:`RESOLUTION_CACHE_TTL` seconds, a
            number is that many. Unlike the memo below it is shared by every
            :class:`Host` and :class:`FQDN`, and is keyed on the name and every
            option; see :func:`netimps.resolve`.
        :param refresh: ask again, and replace the memo with the new answer --
            a name that failed once may resolve later.

        **With none of ``ns``, ``port``, ``tcp``, ``source`` or ``backends`` the
        OS resolver alone answers**, as the standard library's lookups do. A
        missed name then costs milliseconds, where the full chain behind
        :func:`netimps.resolve` costs seconds. Naming any of them hands the
        choice to that chain.

        **A call that passes no option memoises its answer, a miss included**,
        because the common use is several lookups in a row on the same object.
        A call that passes any option, ``cache=`` included, neither reads nor
        writes the memo.
        """
        text = self.value
        if not text:
            if check:
                raise ResolutionError("there is no host to resolve")
            return None

        from ._parse import try_parse

        literal = try_parse(text, IPAddress)
        if literal is not None:
            return literal

        plain = not (
            check
            or ipv6 is not None
            or ns
            or timeout != 5.0
            or port != 53
            or tcp
            or search is not True
            or backends is not None
            or source
            or cache is not False
            or deadline is not None
        )
        if plain and self._attempted and not refresh:
            return self._resolved

        from ._dns import lookup_ip

        found = lookup_ip(
            text,
            check=check,
            ipv6=ipv6,
            ns=ns,
            timeout=timeout,
            port=port,
            tcp=tcp,
            search=search,
            backends=backends,
            source=source,
            cache=cache,
            deadline=deadline,
        )
        if plain:
            object.__setattr__(self, "_attempted", True)
            object.__setattr__(self, "_resolved", found)
        return found

    def resolve(
        self,
        *,
        check: bool = False,
        ipv6: "Optional[bool]" = None,
        ns: "Optional[Union[str, List[str]]]" = None,
        timeout: "Optional[float]" = 5.0,
        port: int = 53,
        tcp: bool = False,
        search: "Union[bool, List[str]]" = True,
        backends: "Optional[Union[str, List[str]]]" = None,
        source: "Optional[Union[str, List[str]]]" = None,
        cache: "Union[bool, float]" = False,
        deadline: "Optional[float]" = None,
    ) -> "Tuple[Optional[FQDN], Optional[IPAddress]]":
        """The pair ``(fqdn, ip)``; whichever half was not found is ``None``.

        =====================  =================================  ==================
        host is                ``fqdn``                           ``ip``
        =====================  =================================  ==================
        a name                 the name as written                forward lookup
        an address             reverse lookup                     the literal
        =====================  =================================  ==================

        The result is always a pair, so ``fqdn, ip = host.resolve()`` never
        fails to unpack. With ``check=True`` a half that could not be found
        raises :class:`ResolutionError` instead. The options are
        :meth:`ip`'s, and a name does its one lookup only.
        """
        return (
            self.fqdn(
                check=check,
                ns=ns,
                timeout=timeout,
                port=port,
                tcp=tcp,
                search=search,
                backends=backends,
                source=source,
                cache=cache,
                deadline=deadline,
            ),
            self.ip(
                check=check,
                ipv6=ipv6,
                ns=ns,
                timeout=timeout,
                port=port,
                tcp=tcp,
                search=search,
                backends=backends,
                source=source,
                cache=cache,
                deadline=deadline,
            ),
        )

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return "Host(%r)" % (self.value,)

    def __bool__(self) -> bool:
        return bool(self.value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Host):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.value)


#: Anything accepted where a single destination (hostname or address) is
#: expected -- ``ping``, ``tcp_check``, ``resolve``'s ``query`` and the like.
#: Not a ``parse()`` target: this is argument coercion, not type-building.
HostLike = Union[
    str,
    IPv4Address,
    IPv6Address,
    IPv4Interface,
    IPv6Interface,
    Host,
    FQDN,
]


def get_hostname(*, fqdn: bool = False) -> str:
    """This machine's host name, asked for when called.

    :func:`platform.node` by default. With ``fqdn=True``,
    :func:`socket.getfqdn`, which **may consult the resolver** and so can
    block; where no qualified name is known it returns the bare one.

    Nothing is read at import: on Windows :func:`platform.node` is a WMI
    query, which is too much to charge every ``import netimps``.
    """
    if fqdn:
        return _socket.getfqdn()
    return _platform.node()


def join_host(host: "HostLike", port: "Optional[int]" = None) -> str:
    """Build ``"host:port"`` from its parts -- the inverse of :func:`split_host`.

    The direction everyone writes by hand and gets wrong on IPv6, because a bare
    v6 address is full of colons and must be bracketed before a port can be
    appended::

        join_host("example.com", 8080)     # 'example.com:8080'
        join_host("10.0.0.5", 8080)        # '10.0.0.5:8080'
        join_host("::1", 8080)             # '[::1]:8080'     -- not '::1:8080'
        join_host("fe80::1%eth0", 80)      # '[fe80::1%eth0]:80'
        join_host("::1")                   # '::1'            -- no port, no brackets
        join_host("example.com")           # 'example.com'

    ``host`` accepts a string, an :class:`IPv4Address`/:class:`IPv6Address`, an
    :class:`IPv4Interface`/:class:`IPv6Interface` (its ``.ip`` is used) or an
    :class:`FQDN`. An already-bracketed string is accepted and not
    double-bracketed.

    **Only an IPv6 *literal* is bracketed.** A hostname never is, however many
    colons someone has put in it -- brackets in a URI authority mean "the thing
    inside is an address", so bracketing a name would produce something no
    resolver will accept.

    Brackets are added when a port is present **or** absent, following the same
    rule: a lone ``"::1"`` needs none, since there is no colon to disambiguate
    from. That is what makes ``split_host(join_host(h, p)) == (h, p)`` hold.

    :raises TypeError: for a network, a value that is not a host type, or a
        ``port`` that is not an ``int`` (a ``bool`` is not one).
    :raises NetimpsValueError: for an empty host, brackets around anything but
        an IPv6 address, or a port outside 0-65535.
    """
    text = _host_text(host).strip()
    if not text:
        raise NetimpsValueError("host must not be empty")

    if text.startswith("[") or text.endswith("]"):
        # A mismatched bracket has to raise, not fall through: `"[::1"` is not an
        # IPv6 literal, so it would otherwise emerge unbracketed as `"[::1:80"`,
        # which is garbage the caller cannot detect. `split_host` rejects the
        # same input, and the pair must agree.
        if not (text.startswith("[") and text.endswith("]")):
            raise NetimpsValueError("mismatched brackets in %r" % (text,))
        # Already bracketed: validate the inside rather than trusting it, so a
        # malformed literal is caught here and not by the caller's resolver.
        if not _is_ipv6_literal(text[1:-1]):
            raise NetimpsValueError("%r is bracketed but not an IPv6 address" % (text,))
        text = text[1:-1]

    if _is_ipv6_literal(text):
        text = "[%s]" % (text,)

    if port is None:
        # Strip the brackets back off: with no port there is nothing to
        # disambiguate, and `split_host` returns the bare form, so keeping
        # them would break the round trip.
        return text[1:-1] if text.startswith("[") else text

    return "%s:%d" % (text, _port_number(port, port))


def unmap(value: "IPAddressLike") -> "IPAddress":
    """Collapse an IPv4-mapped IPv6 address to plain IPv4; pass anything else through.

    ``::ffff:10.0.0.5`` is how a dual-stack socket reports an IPv4 peer, and
    almost nothing a caller does wants it in that form -- an ACL comparing against
    ``10.0.0.0/8``, a log line, a config lookup::

        unmap("::ffff:10.0.0.5")    # IPv4Address('10.0.0.5')
        unmap("10.0.0.5")           # IPv4Address('10.0.0.5')   -- unchanged
        unmap("2001:db8::1")        # IPv6Address('2001:db8::1') -- unchanged

    Built on :attr:`ipaddress.IPv6Address.ipv4_mapped` rather than stripping a
    ``"::ffff:"`` prefix from the text. The string version looks equivalent and
    is not -- measured, these are all genuinely mapped addresses that a
    ``startswith("::ffff:") and "." in text`` test leaves untouched:

    ===========================  ==========  ============================
    input                        this gives  the string test gives
    ===========================  ==========  ============================
    ``::FFFF:10.0.0.5``          ``10.0.0.5``  unchanged (wrong case)
    ``::ffff:0:1``               ``0.0.0.1``   unchanged (no dot)
    ``0:0:0:0:0:ffff:0a00:0005`` ``10.0.0.5``  unchanged (expanded form)
    ===========================  ==========  ============================

    One address has many spellings, and only the parsed form sees through them.

    :raises NetimpsValueError: for text that is no address.
    :raises TypeError: for a value that is no address type.
    """
    address = _as_address(value)
    if isinstance(address, IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None:
            return mapped
    return address


def is_wildcard(value: "Union[IPAddressLike, None]") -> bool:
    """Whether ``value`` means "every local address" -- the bind-anything form.

    True for ``""``, ``None``, ``"0.0.0.0"``, ``"::"`` and any other spelling
    whose address form is unspecified (``"::0"``, ``"0000::0"``), and for the
    v4-mapped ``::ffff:0.0.0.0``::

        is_wildcard("")           # True -- what bind("") means
        is_wildcard("0.0.0.0")    # True
        is_wildcard("::")         # True
        is_wildcard("127.0.0.1")  # False

    A ``%zone`` suffix does not change whether the address is unspecified.

    :raises NetimpsValueError: for text that is no address.
    :raises TypeError: for a value of another type.
    """
    if value is None:
        return True
    if isinstance(value, str):
        value = value.strip().split("%", 1)[0]
        if not value:
            return True
    return bool(unmap(_as_address(value)).is_unspecified)
