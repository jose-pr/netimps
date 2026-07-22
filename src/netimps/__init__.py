"""netimps -- small, self-contained network utilities.

A thin, typed convenience layer over the standard library's :mod:`ipaddress`
plus a handful of host helpers (DNS lookup, ping, interface discovery). One
flat import surface; the only runtime dependency is ``dnspython``, used solely
inside :func:`nslookup`.

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
from typing import Callable, List, Optional, TypeVar, Union

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
    "parse_ip",
    "parse_network",
    "get_ip",
    "is_loopback_or_link_local",
    "get_default_port",
    "nslookup",
    "resolve",
    "ping",
    "Interface",
    "get_interfaces",
    "active_nic_addresses",
    "get_ip_address",
    "nic_info",
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


def parse_ip(value: Optional[_AddressValue]) -> Optional[IPAddress]:
    """Coerce ``value`` to an :class:`ipaddress` address, tolerating emptiness.

    Returns ``None`` for ``None`` or an empty/whitespace-only string -- callers
    frequently hold an as-yet-unresolved ``ip`` field (``""``) and pass it
    straight through, so an empty value maps to a falsy ``None`` rather than
    raising. Any other value is delegated to :func:`IPAddr`, which raises
    :class:`ValueError` on genuinely malformed input.

    Note the difference from :func:`try_parse`: *only* emptiness becomes
    ``None`` here -- malformed input still raises, so a typo is not silently
    swallowed. Use ``try_parse(value, IPAddr)`` when you want every failure to
    yield ``None``.
    """
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    return IPAddr(value)


def parse_network(value: Optional[_NetworkValue]) -> Optional[IPNetwork]:
    """Coerce ``value`` to an :class:`ipaddress` network (non-strict).

    Mirrors :func:`parse_ip`: ``None`` or an empty string yields ``None``;
    anything else is delegated to :func:`IPNet`.
    """
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    return IPNet(value)


_T = TypeVar("_T")


def try_parse(value: object, parser: Callable[..., _T]) -> Optional[_T]:
    """Return ``parser(value)``, or ``None`` if it rejects the input. Never raises.

    The generic non-raising parse behind :func:`parse_ip` and
    :func:`parse_network`, usable with any of this module's factories -- or any
    callable that signals bad input with ``ValueError``/``TypeError``::

        try_parse("10.0.0.5", IPAddr)        # IPv4Address('10.0.0.5')
        try_parse("nonsense", IPAddr)        # None
        try_parse(user_input, MACAddress) or DEFAULT_MAC

    Prefer this to ``is_valid`` followed by a parse: that pattern does the work
    twice and leaves a window where the two disagree.

    Only ``ValueError`` and ``TypeError`` are swallowed -- the two exceptions
    that mean "bad input". Anything else (an ``OSError`` from a parser that
    touches the network, a bug in the parser) propagates, because turning it
    into ``None`` would disguise a real failure as a rejected value.
    """
    try:
        return parser(value)
    except (ValueError, TypeError):
        return None


def is_valid(value: object, parser: Callable[..., object]) -> bool:
    """Return ``True`` if ``parser(value)`` succeeds. Never raises.

    The generic "can this be parsed?" check behind :func:`is_valid_ip` and
    :func:`is_valid_mac`::

        is_valid("10.0.0.5", IPAddr)         # True
        is_valid("10.0.0.0/24", IPNet)       # True
        is_valid("aa:bb:cc:dd:ee:ff", MACAddress)
        is_valid("nonsense", IPAddr)         # False

    When you want the parsed value too, use :func:`try_parse` instead of
    calling this first -- one call, no double work. Same exception policy: only
    ``ValueError``/``TypeError`` count as "invalid".

    .. note::
       A parser that legitimately returns ``None`` for valid input would be
       indistinguishable from failure via :func:`try_parse`; this function
       reports such a case as ``True``, since the parse did succeed.
    """
    try:
        parser(value)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_ip(value: object) -> bool:
    """Return ``True`` if ``value`` is a valid IPv4/IPv6 address.

    Never raises: any input that :func:`ipaddress.ip_address` rejects (including
    non-string types and empty strings) yields ``False``. Shorthand for
    ``is_valid(value, IPAddr)``.
    """
    return is_valid(value, _ipaddress.ip_address)


def is_valid_network(value: object) -> bool:
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
        r"|[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2}"     # dot / Cisco triplets
        r"|[0-9A-Fa-f]{12}"                            # bare, no separators
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


def is_valid_mac(value: object) -> bool:
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
       Not the same as :func:`parse_ip`, and the difference matters: ``parse_ip``
       never touches the network, while this **may block on DNS**. Use
       ``parse_ip`` to validate user input; use ``get_ip`` when you genuinely
       want a name resolved.
    """
    try:
        try:
            return _ipaddress.ip_address(address)
        except ValueError:
            return _ipaddress.ip_address(_socket.gethostbyname(address))
    except (ValueError, OSError):
        return None


def is_loopback_or_link_local(ip: IPAddress) -> bool:
    """True for loopback (``127/8``, ``::1``) or link-local (``169.254/16``, ``fe80::/10``).

    These two categories share a practical property: neither can usefully be
    routed off the local host or link, so proxying, forwarding or advertising
    them is always wrong. Keeping the definition in one place stops each caller
    from writing a subtly different version.
    """
    return ip.is_loopback or ip.is_link_local


#: Conventional ports for schemes :func:`socket.getservbyname` gets wrong or
#: does not know (it has no entry for the socks variants).
_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "ftp": 21,
    "socks": 1080,
    "socks4": 1080,
    "socks5": 1080,
}


def get_default_port(scheme: str) -> Optional[int]:
    """Return the conventional port for a URL scheme, or ``None`` if unknown.

    Checks a small built-in table first, then falls back to the system services
    database via :func:`socket.getservbyname`::

        get_default_port("https")    # 443
        get_default_port("socks5")   # 1080  (absent from /etc/services)
        get_default_port("nope")     # None
    """
    scheme = scheme.lower()
    if scheme in _DEFAULT_PORTS:
        return _DEFAULT_PORTS[scheme]
    try:
        return _socket.getservbyname(scheme)
    except OSError:
        return None


# ---------------------------------------------------------------------------
# DNS / reachability
# ---------------------------------------------------------------------------

def nslookup(
    query: str,
    ns: Optional[Union[str, List[str]]] = None,
    type: str = "a",
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
) -> List[str]:
    """Resolve ``query`` via DNS and return the answers as a list of strings.

    Contract: always returns a ``list`` of string records (e.g. one or more
    ``"93.184.216.34"`` for an ``A`` lookup), and an **empty list** when the
    name does not resolve or any DNS error occurs -- never ``None``. Callers can
    therefore write ``if result:`` and index ``result[0]`` safely.

    :param query: the name (or address, for reverse types) to look up.
    :param ns: optional nameserver, or list of nameservers, to query instead of
        the system resolver.
    :param type: DNS record type (``"a"``, ``"aaaa"``, ``"mx"`` ...). Shadows the
        ``type`` builtin -- kept for backwards compatibility; :func:`resolve`
        spells it ``rdtype``.
    :param timeout: seconds to spend on the whole resolution, retries included
        (``None`` for dnspython's default). Bounds *total* time, not each query
        -- a list of unreachable nameservers cannot stretch past it.
    :param port: nameserver port, for resolvers not on 53.
    :param tcp: query over TCP instead of UDP. Useful for large responses that
        would otherwise be truncated.

    A genuine lookup failure (NXDOMAIN, no answer, timeout, all servers failed)
    yields ``[]``; a malformed query or unknown record type raises
    :class:`ValueError`, since that is a caller bug rather than a DNS result.

    .. note::
       :func:`resolve` is the preferred spelling -- same behaviour, but the
       record type comes second, where callers actually want it.

    Requires the ``dnspython`` package (installed with ``netimps``).
    """
    return _resolve(query, ns=ns, rdtype=type, timeout=timeout, port=port, tcp=tcp)


def _resolve(
    query: str,
    ns: Optional[Union[str, List[str]]] = None,
    rdtype: str = "a",
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
) -> List[str]:
    """Shared implementation behind :func:`nslookup` and :func:`resolve`."""
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


def resolve(
    query: str,
    rdtype: str = "a",
    ns: Optional[Union[str, List[str]]] = None,
    timeout: Optional[float] = 5.0,
    port: int = 53,
    tcp: bool = False,
) -> List[str]:
    """Resolve ``query`` via DNS -- the same lookup as :func:`nslookup`, better named.

    ``nslookup`` is named after the (long-deprecated) command-line tool and puts
    the nameserver before the record type. This is the preferred spelling: the
    record type is the argument callers actually vary::

        resolve("example.com")                    # ['93.184.216.34']
        resolve("example.com", "aaaa")
        resolve("example.com", "mx", ns="1.1.1.1")

    Same contract as :func:`nslookup` -- a list of strings, ``[]`` on any
    lookup failure, never ``None``. See that function for the parameters.
    """
    return _resolve(query, ns=ns, rdtype=rdtype, timeout=timeout, port=port, tcp=tcp)


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


# ---------------------------------------------------------------------------
# Local NIC discovery
# ---------------------------------------------------------------------------

def active_nic_addresses() -> List[IPv4Address]:
    """Return the host's active (non-loopback) IPv4 address as a 1-element list.

    Resolves the local hostname and filters out ``127.*`` loopback entries.
    Returns an empty list if only loopback addresses are found. Cross-platform.
    """
    try:
        _, _, ips = _socket.gethostbyname_ex(_socket.gethostname())
    except OSError:
        return []
    return [IPv4Address(ip) for ip in ips if not ip.startswith("127.")][:1]


def get_ip_address(nic_name: str) -> str:
    """Return the IPv4 address bound to interface ``nic_name`` (POSIX only).

    Uses an ``SIOCGIFADDR`` ioctl and therefore requires the POSIX-only
    :mod:`fcntl` module. Raises :class:`OSError` (``NotImplementedError`` under
    Windows, where ``fcntl`` is unavailable).
    """
    import struct

    try:
        import fcntl
    except ImportError as exc:  # pragma: no cover - platform dependent
        raise NotImplementedError("get_ip_address requires POSIX fcntl") from exc

    s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    try:
        return _socket.inet_ntoa(
            fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack("256s", nic_name[:15].encode("utf-8")),
            )[20:24]
        )
    finally:
        s.close()


def nic_info() -> List[tuple]:
    """Return ``[(name, ipv4), ...]`` for each interface (POSIX only).

    Enumerates interfaces via :func:`socket.if_nameindex` (POSIX only) and pairs
    each with its :func:`get_ip_address`. Raises on platforms without these
    facilities (e.g. Windows).
    """
    if not hasattr(_socket, "if_nameindex"):  # pragma: no cover - platform dependent
        raise NotImplementedError("nic_info requires POSIX socket.if_nameindex")
    return [(name, get_ip_address(name)) for _, name in _socket.if_nameindex()]


# Imported last: _ifaddrs builds MACAddress objects, so it must load after the
# class above exists.
from ._ifaddrs import Interface, get_interfaces  # noqa: E402
