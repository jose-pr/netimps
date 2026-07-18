"""netutils -- small, self-contained network utilities.

A thin, typed convenience layer over the standard library's :mod:`ipaddress`
plus a handful of host helpers (DNS lookup, ping, local NIC discovery).

The public surface is intentionally flat::

    import netutils

    netutils.IPAddress("10.0.0.5")
    netutils.MACAddress("AA:BB:CC:DD:EE:FF").as_str("-")
    netutils.parse_network("192.168.1.0/24")
    netutils.nslookup("example.com")

All IP/network types are the concrete :mod:`ipaddress` classes (or thin
factories over them), so ``.exploded``, ``.network_address``, ``.netmask`` and
``addr in network`` membership all behave exactly as the stdlib does.
"""

from __future__ import annotations

import ipaddress as _ipaddress
import os as _os
import platform as _platform
import re as _re
import socket as _socket
from subprocess import run as _run
from typing import List, Optional, Union

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
    "parse_ip",
    "parse_network",
    "is_valid_ip",
    "nslookup",
    "ping",
    "active_nic_addresses",
    "get_ip_address",
    "nic_info",
    "HOST_DN",
]

__version__ = "0.1.0"

#: Fully-qualified (or short) name of the host running this process.
HOST_DN = _platform.node()

# Type aliases describing the values these factories accept / return. Kept as
# runtime objects (not just annotations) so they read well in tracebacks.
_AddressValue = Union[str, int, "_ipaddress._BaseAddress"]
_NetworkValue = Union[str, int, "_ipaddress._BaseNetwork", "_ipaddress._BaseAddress"]


# ---------------------------------------------------------------------------
# IP address / interface / network factories
# ---------------------------------------------------------------------------

def IPAddress(value: _AddressValue) -> Union[IPv4Address, IPv6Address]:
    """Return an :class:`ipaddress.IPv4Address`/:class:`IPv6Address`.

    Accepts a string (``"10.0.0.5"``), a packed/integer form, or an existing
    address object (returned as-is by the stdlib). This is a factory, not a
    class -- ``isinstance(x, IPAddress)`` is not meaningful; test against
    ``IPv4Address``/``IPv6Address`` instead.
    """
    return _ipaddress.ip_address(value)


def IPInterface(value: _AddressValue) -> Union[IPv4Interface, IPv6Interface]:
    """Return an :class:`ipaddress.IPv4Interface`/:class:`IPv6Interface`.

    An interface carries both a host address and its network, exposing ``.ip``,
    ``.netmask`` and ``.network`` (each with ``.exploded``), e.g.::

        IPInterface("10.0.0.5/24").network.network_address.exploded
    """
    return _ipaddress.ip_interface(value)


def IPNetwork(value: _NetworkValue, strict: bool = False) -> Union[IPv4Network, IPv6Network]:
    """Return an :class:`ipaddress.IPv4Network`/:class:`IPv6Network`.

    Defaults to ``strict=False`` so a host address with a prefix (e.g.
    ``"10.0.0.5/24"``) is accepted and normalised to its network rather than
    raising. Supports ``.network_address``, ``.netmask`` and ``addr in network``
    membership tests.
    """
    return _ipaddress.ip_network(value, strict=strict)


def parse_ip(value: Optional[_AddressValue]) -> Optional[Union[IPv4Address, IPv6Address]]:
    """Coerce ``value`` to an :class:`ipaddress` address, tolerating emptiness.

    Returns ``None`` for ``None`` or an empty/whitespace-only string -- callers
    frequently hold an as-yet-unresolved ``ip`` field (``""``) and pass it
    straight through, so an empty value maps to a falsy ``None`` rather than
    raising. Any other value is delegated to :func:`IPAddress`, which raises
    :class:`ValueError` on genuinely malformed input.
    """
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    return IPAddress(value)


def parse_network(value: Optional[_NetworkValue]) -> Optional[Union[IPv4Network, IPv6Network]]:
    """Coerce ``value`` to an :class:`ipaddress` network (non-strict).

    Mirrors :func:`parse_ip`: ``None`` or an empty string yields ``None``;
    anything else is delegated to :func:`IPNetwork`.
    """
    if value is None:
        return None
    if isinstance(value, str) and not value.strip():
        return None
    return IPNetwork(value)


def is_valid_ip(value: object) -> bool:
    """Return ``True`` if ``value`` is a valid IPv4/IPv6 address.

    Never raises: any input that :func:`ipaddress.ip_address` rejects (including
    non-string types and empty strings) yields ``False``.
    """
    try:
        _ipaddress.ip_address(value)  # type: ignore[arg-type]
        return True
    except (ValueError, TypeError):
        return False


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

    def __init__(self, value: Union[str, int, bytes, "MACAddress"]) -> None:
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

    def as_str(self, sep: str = ":") -> str:
        """Return the MAC as a lowercase string with ``sep`` between octets."""
        return sep.join("%02x" % b for b in self._octets)

    @property
    def packed(self) -> bytes:
        """The 6 raw bytes of the address."""
        return self._octets

    def __int__(self) -> int:
        return int.from_bytes(self._octets, "big")

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


# ---------------------------------------------------------------------------
# DNS / reachability
# ---------------------------------------------------------------------------

def nslookup(query: str, ns: Optional[Union[str, List[str]]] = None, type: str = "a") -> List[str]:
    """Resolve ``query`` via DNS and return the answers as a list of strings.

    Contract: always returns a ``list`` of string records (e.g. one or more
    ``"93.184.216.34"`` for an ``A`` lookup), and an **empty list** when the
    name does not resolve or any DNS error occurs -- never ``None``. Callers can
    therefore write ``if result:`` and index ``result[0]`` safely.

    :param query: the name (or address, for reverse types) to look up.
    :param ns: optional nameserver, or list of nameservers, to query instead of
        the system resolver.
    :param type: DNS record type (``"a"``, ``"aaaa"``, ``"mx"`` ...).

    Requires the ``dnspython`` package (installed with ``netutils``).
    """
    from dns import resolver as _resolver

    r = _resolver.Resolver(configure=not ns)
    if isinstance(ns, str):
        ns = [ns]
    if ns:
        r.nameservers = list(ns)
    try:
        answer = r.resolve(query, type)
    except Exception:
        return []
    return [str(record) for record in answer]


def ping(hostname: str, tries: int = 1) -> bool:
    """Return ``True`` if ``hostname`` answers a single ICMP echo within ``tries``.

    Shells out to the platform ``ping`` (Windows ``-n``/``-w`` vs POSIX
    ``-c``/``-W``), sending one packet per attempt with a 1s timeout, and
    returns on the first success. An empty ``hostname`` is ``False``.
    """
    if not hostname:
        return False
    if _os.name == "nt":
        options = ["-n", "1", "-w", "1000"]
    else:
        options = ["-c", "1", "-W", "1", "-n"]
    tries = tries or 1
    while tries > 0:
        response = _run(["ping", *options, hostname], capture_output=True)
        if response.returncode == 0:
            return True
        tries -= 1
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
