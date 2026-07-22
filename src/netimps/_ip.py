"""IP address, interface and network types (internal).

The v4/v6 union aliases callers annotate with, the builder tables :func:`parse`
dispatches on, and the address/network helpers that are specific to IP (as
opposed to the generic parsing combinators, which live in ``__init__``).

Re-exported from :mod:`netimps`.
"""

from __future__ import annotations

import ipaddress as _ipaddress
import socket as _socket
from typing import List, Optional, Tuple, Union

from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)

__all__ = [
    "Host",
    "APIPA",
    "LOOPBACK_V4",
    "LOOPBACK_V6",
    "LINK_LOCAL_V6",
    "IPAddress",
    "IPInterface",
    "IPNetwork",
    "IPAddressLike",
    "IPNetworkLike",
    "IPv4Address",
    "IPv4Interface",
    "IPv4Network",
    "IPv6Address",
    "IPv6Interface",
    "IPv6Network",
    "get_ip",
    "collapse",
    "subtract",
    "normalize_host",
    "is_link_scoped",
]

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


# Internal aliases kept as runtime objects (not just annotations) so they read
# well in tracebacks; the public spellings above are what callers should use.
_AddressValue = Union[str, int, "_ipaddress._BaseAddress"]
_NetworkValue = Union[str, int, "_ipaddress._BaseNetwork", "_ipaddress._BaseAddress"]


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
    from . import parse as _parse

    v4, v6 = [], []
    for item in networks:
        net = _parse(item, IPNetwork)
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
    from . import parse as _parse

    remaining = collapse(networks)
    for item in remove:
        excluded = _parse(item, IPNetwork)
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


def normalize_host(
    text: str, default_port: Optional[int] = None
) -> "Tuple[str, Optional[int]]":
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


# ---------------------------------------------------------------------------
# Well-known networks
# ---------------------------------------------------------------------------
# Named so callers read as the RFC does, instead of repeating literals. These
# are the ranges consumers kept spelling out by hand.

#: RFC 3927 link-local ("Automatic Private IP Addressing") -- what a host gives
#: itself when DHCP fails, so its presence usually means "no lease".
APIPA = _ipaddress.ip_network("169.254.0.0/16")

#: RFC 1122 loopback. Note this is the whole /8, not just 127.0.0.1.
LOOPBACK_V4 = _ipaddress.ip_network("127.0.0.0/8")

#: The single IPv6 loopback address, as a network for symmetry.
LOOPBACK_V6 = _ipaddress.ip_network("::1/128")

#: RFC 4291 IPv6 link-local.
LINK_LOCAL_V6 = _ipaddress.ip_network("fe80::/10")


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
    still be rebuilt when resolution fails -- which is the case a bare
    ``get_ip()`` handles badly, since it returns ``None`` and loses the name.
    """

    __slots__ = ("value", "_resolved", "_attempted")

    def __init__(self, value) -> None:
        if isinstance(value, Host):
            value = value.value
        self.value = "" if value is None else str(value).strip()
        self._resolved = None
        self._attempted = False

    @property
    def is_address(self) -> bool:
        """True if the value is already an IP literal -- no DNS needed."""
        from . import is_valid

        return is_valid(self.value, IPAddress)

    def ip(self, refresh: bool = False):
        """Resolve to an address, or ``None``.

        A literal is parsed directly; a hostname goes to DNS. **The result is
        cached**, including a failure, because the common use is several
        lookups in a row on the same object. Pass ``refresh=True`` to retry --
        a name that failed once may resolve later.
        """
        if refresh:
            self._attempted = False
            self._resolved = None
        if self._attempted:
            return self._resolved

        self._attempted = True
        if not self.value:
            self._resolved = None
            return None

        from . import get_ip, try_parse

        literal = try_parse(self.value, IPAddress)
        self._resolved = literal if literal is not None else get_ip(self.value)
        return self._resolved

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
