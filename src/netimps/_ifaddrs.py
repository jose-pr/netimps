"""Native network-interface enumeration (internal).

Enumerates the host's interfaces -- adapter name, MAC, and every address with
its *real* prefix length -- using nothing but the standard library. POSIX goes
through ``getifaddrs(3)``; Windows through ``GetAdaptersAddresses``. Both are
bound with :mod:`ctypes`, so the package has no third-party dependency (the
widely used ``ifaddr`` package solves the same problem, and is deliberately
*not* used here).

The public entry point is :func:`get_interfaces`, re-exported from
:mod:`netimps`. Do not depend on this module path from outside the package.

Normalisation is the whole point
--------------------------------
The platforms disagree about far more than struct layout, so all of it is
resolved here rather than in every caller:

===================  ==================  ==================  =================
Concern              Linux               macOS/BSD           Windows
===================  ==================  ==================  =================
Interface name       ``eth0``            ``en0``             GUID + friendly
Prefix src        netmask sockaddr    netmask sockaddr    ``OnLinkPrefixLength``
Link-layer family    ``AF_PACKET`` (17)  ``AF_LINK`` (18)    ``PhysicalAddress``
IPv6 scope           ``%1``              ``%en0``            ``%12``
Loopback name        ``lo``              ``lo0``             ``Loopback Pseudo-Interface 1``
===================  ==================  ==================  =================

Two consequences worth stating outright, because getting them wrong is subtle:

* ``Interface.is_loopback`` comes from the kernel's own flag -- ``IFF_LOOPBACK``
  on POSIX, ``IF_TYPE_SOFTWARE_LOOPBACK`` on Windows -- and never from the
  name: a ``name == "lo"`` test silently fails on macOS (``lo0``) and is
  meaningless on Windows. The address heuristic remains only as the fallback
  for the degraded enumeration path, which reports no flags; it is wrong
  wherever a loopback interface *also* carries a routable address, which WSL2
  does by default (``10.255.255.254/32`` on ``lo``) and every keepalived /
  anycast / VIP host does on purpose.
* Prefixes are always real prefix lengths. The POSIX netmask sockaddr is
  converted by counting bits; Windows already reports an integer. Either way
  ``iface.ips[0].network`` behaves identically.

Platform-native leftovers (adapter GUID, ``IFF_*`` flags, ...) are available
only via ``get_interfaces(raw=True)`` -- see :class:`Interface.raw`.
"""

from __future__ import annotations

import ctypes as _ctypes
from functools import partial as _partial
import ipaddress as _ipaddress
import socket as _socket
import struct as _struct
import sys as _sys
import threading as _threading
import time as _time
from ctypes import (
    POINTER,
    Structure,
    c_char,
    c_char_p,
    c_int,
    c_uint8,
    c_uint16,
    c_uint32,
    c_ulong,
    c_void_p,
)
from ._mac import MACAddress
from typing import (
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Sequence,
    Tuple,
    Union,
)
from ._ip import unmap
from ._parse import try_parse

__all__ = [
    "Interface",
    "get_interfaces",
    "iter_addresses",
    "is_broadcast",
    "clear_interface_cache",
    "interface_enumerations",
    "INTERFACE_CACHE_TTL",
]

_IPInterface = Union[_ipaddress.IPv4Interface, _ipaddress.IPv6Interface]

#: True on macOS and the BSDs, whose ``sockaddr`` carries a leading ``sa_len``
#: byte that Linux does not have. See ``_SockaddrHeader`` below -- this single
#: flag is the difference between reading the address family correctly and
#: silently skipping every address on those platforms.
_HAS_SA_LEN = _sys.platform.startswith(("darwin", "freebsd", "openbsd", "netbsd"))

_IS_WINDOWS = _sys.platform == "win32"

# Link-layer families carrying the MAC. Linux uses AF_PACKET with sockaddr_ll;
# macOS/BSD use AF_LINK with sockaddr_dl. Neither constant is exposed portably
# by the socket module, hence the literals.
_AF_PACKET = 17  # Linux
_AF_LINK = 18  # macOS / BSD

#: ``IFF_LOOPBACK`` in ``ifa_flags``. Same value (8) on Linux and on the BSDs.
_IFF_LOOPBACK = 0x8
#: ``IF_TYPE_SOFTWARE_LOOPBACK`` in ``IP_ADAPTER_ADDRESSES.IfType`` (IANA
#: ifType 24), the Windows spelling of the same fact.
_IF_TYPE_SOFTWARE_LOOPBACK = 24


#: What an MTU of ULONG max is reported as. The IP total-length field is 16 bits,
#: so 65535 is the largest datagram that can exist whatever the link allows --
#: making this a clamp to reality rather than an invented number. It yields
#: exactly 65507 through :func:`netimps.max_udp_payload`, which is the measured
#: largest UDP payload loopback actually delivers.
_UNBOUNDED_MTU = 65535


class Interface:
    """One network interface, normalised to be identical across platforms.

    Attributes:
        name: Human-usable adapter name (``"eth0"``, ``"en0"``, or the Windows
            *friendly* name -- never the raw GUID).
        index: :func:`socket.if_nametoindex` value, or ``0`` when unknown.
        mac: The hardware address, or ``None`` for interfaces without one
            (loopback, tunnels). An all-zero address is normalised to ``None``:
            Linux reports the loopback MAC as ``00:00:00:00:00:00`` where
            macOS and Windows report nothing at all, and ``mac is None`` should
            mean the same thing on every platform.
        ips: Every address bound to the interface, each as an
            ``IPv4Interface``/``IPv6Interface`` carrying its real prefix.
        mtu: Link MTU in bytes, or ``None`` when the platform genuinely could
            not read one. An **unbounded** MTU is not ``None``: the Windows
            loopback adapter reports ULONG max, meaning there is no link to
            constrain it, and that is reported as 65535 -- the largest datagram
            the 16-bit IP total-length field can describe, so a clamp to reality
            rather than an invented figure. Measured: that interface really does
            carry a 65507-octet UDP payload, which is what
            :func:`netimps.max_udp_payload` derives from it, and Linux reports its
            own ``lo`` as 65536 rather than as nothing. This is the **link** MTU;
            for a path see :func:`netimps.discover_mtu`.
        is_loopback: The kernel's own loopback flag (``IFF_LOOPBACK`` on POSIX,
            ``IF_TYPE_SOFTWARE_LOOPBACK`` on Windows) when the enumeration
            reported one; otherwise derived from the addresses. The constructor
            argument of the same name is ``None`` for "not reported" -- the
            degraded enumeration path, and objects built by hand.
        raw: ``None`` unless enumerated with ``get_interfaces(raw=True)``, in
            which case a platform-specific dict of leftovers. **Not portable**
            and explicitly outside the stability guarantee.
    """

    __slots__ = ("name", "index", "mac", "ips", "mtu", "_is_loopback", "raw")

    name: str
    index: int
    mac: "Optional[MACAddress]"
    ips: "Tuple[_IPInterface, ...]"
    mtu: "Optional[int]"
    _is_loopback: "Optional[bool]"
    raw: "Optional[Dict[str, Any]]"

    def __init__(
        self,
        name: str,
        index: int = 0,
        *,
        mac: "Optional[MACAddress]" = None,
        ips: "Optional[Iterable[_IPInterface]]" = None,
        mtu: "Optional[int]" = None,
        raw: "Optional[Dict[str, Any]]" = None,
        is_loopback: "Optional[bool]" = None,
    ) -> None:
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "index", index)
        object.__setattr__(self, "mac", mac)
        object.__setattr__(self, "ips", () if ips is None else tuple(ips))
        object.__setattr__(self, "mtu", mtu)
        object.__setattr__(self, "_is_loopback", is_loopback)
        object.__setattr__(self, "raw", raw)

    def __reduce__(self) -> "Tuple[Any, Tuple[Any, ...]]":
        """Pickle and copy through the constructor.

        ``__slots__`` plus a blocked ``__setattr__`` defeats the default
        restore, which assigns the slots back onto a blank instance.
        """
        return (
            _partial(
                Interface,
                self.name,
                self.index,
                mac=self.mac,
                ips=self.ips,
                mtu=self.mtu,
                raw=self.raw,
                is_loopback=self._is_loopback,
            ),
            (),
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Interface is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Interface is immutable")

    @property
    def is_loopback(self) -> bool:
        """True when this is the loopback interface.

        The kernel's own answer when there is one: ``IFF_LOOPBACK`` on POSIX,
        ``IF_TYPE_SOFTWARE_LOOPBACK`` on Windows, captured during
        enumeration. Never the name -- ``lo`` (Linux),
        ``lo0`` (macOS) and ``Loopback Pseudo-Interface 1`` (Windows) share no
        common spelling.

        Falls back to the addresses only when the flag was not reported (the
        degraded enumeration path reports no flags, and neither do hand-built
        objects). That fallback requires *a* loopback address and **no routable
        one**, which is a guess rather than an answer: WSL2 binds a routable
        ``10.255.255.254/32`` to ``lo`` on every installation, and binding a
        service address to the loopback interface is the standard
        keepalived/anycast pattern -- on such a host the heuristic reports that
        there is no loopback interface at all. Link-local addresses are ignored
        by it, since macOS's ``lo0`` also carries ``fe80::1/64`` and a
        non-routable address cannot make an interface non-loopback.
        """
        if self._is_loopback is not None:
            return self._is_loopback
        if not self.ips:
            return False
        has_loopback = False
        for entry in self.ips:
            if entry.ip.is_loopback:
                has_loopback = True
            elif not entry.ip.is_link_local:
                return False  # a routable address: not the loopback interface
        return has_loopback

    def primary_ip(
        self, ipv6: bool = False, loopback_ok: bool = True
    ) -> "Optional[_IPInterface]":
        """Pick the one entry that best represents this interface, or ``None``.

        Answers "which of this adapter's addresses do I use?" -- the question
        ``IP_MULTICAST_IF``, a bind target and ``ping -S`` all ask::

            iface.primary_ip()               # IPv4Interface('10.0.0.5/24')
            iface.primary_ip().ip            # IPv4Address('10.0.0.5')
            iface.primary_ip(ipv6=True)      # its IPv6 entry instead

        **Ranked, not first-non-loopback: routable, then loopback, then
        link-local**, keeping the OS order within a rank. The rank matters
        because an interface commonly lists a link-local address *before* its
        routable one -- ``fe80::`` is configured first on Linux and macOS NICs
        -- and "the first entry that is not loopback" therefore picked an
        address that is useless as a bind target and unreachable off-link.

        **Loopback outranks link-local deliberately**, which is not the obvious
        order. The only interface that carries both is the loopback adapter, and
        there ``::1`` is the address every caller means; a real NIC has no
        loopback entry, so the rank never takes anything from it. A NIC holding
        *only* a link-local address -- before SLAAC completes, say -- still
        yields it, because there is nothing else to yield. With
        ``loopback_ok=False`` the loopback rank is skipped entirely, so such a
        caller still gets the link-local in preference to ``None``.

        Measured on a macOS loopback adapter, whose entries are
        ``127.0.0.1/8``, ``::1/128``, ``fe80::1/64``: the old rule returned
        ``fe80::1`` for ``ipv6=True`` where ``::1`` is wanted, and
        ``bind(interface=...)`` then failed with "Can't assign requested
        address". On a NIC listing ``fe80::`` before a global address it
        returned the link-local in preference to the global one.

        Link-local covers ``fe80::/10`` and IPv4 ``169.254.0.0/16`` -- LINK_LOCAL_V4 is
        the same problem wearing the other family's clothes, and an interface
        holding both an LINK_LOCAL_V4 address and a DHCP lease should answer with the
        lease.

        Named *primary* rather than *ip* because this is a **selection**, not
        "the" address: an interface routinely has several, and the full lists
        remain on :attr:`ips` / :attr:`ipv4` / :attr:`ipv6`.

        :param ipv6: pick from :attr:`ipv6` rather than :attr:`ipv4`.
        :param loopback_ok: when False, an interface holding only loopback
            addresses yields ``None`` instead -- for callers that need a
            routable address specifically.

        Returns an ``IPv4Interface``/``IPv6Interface``, the **same element type
        as** :attr:`ips` -- one of them, not a different shape. Use ``.ip`` for
        the bare address that socket options take.
        """
        candidates = self.ipv6 if ipv6 else self.ipv4
        if not candidates:
            return None

        # Three ranks rather than a loopback test, and stable within each so the
        # OS order still decides between two equals.
        routable, link_local, loopback = [], [], []
        for entry in candidates:
            if entry.ip.is_loopback:
                loopback.append(entry)
            elif entry.ip.is_link_local:
                link_local.append(entry)
            else:
                routable.append(entry)

        if routable:
            return routable[0]
        if loopback and loopback_ok:
            # Before link-local: the only interface holding both is loopback
            # itself, where `::1` is what every caller means.
            return loopback[0]
        if link_local:
            return link_local[0]
        return None

    @property
    def ipv4(self) -> "List[_ipaddress.IPv4Interface]":
        """Just the IPv4 addresses."""
        return [ip for ip in self.ips if isinstance(ip, _ipaddress.IPv4Interface)]

    @property
    def ipv6(self) -> "List[_ipaddress.IPv6Interface]":
        """Just the IPv6 addresses."""
        return [ip for ip in self.ips if isinstance(ip, _ipaddress.IPv6Interface)]

    def __repr__(self) -> str:
        return "Interface(name=%r, index=%r, mac=%r, ips=%r, mtu=%r)" % (
            self.name,
            self.index,
            None if self.mac is None else str(self.mac),
            [str(ip) for ip in self.ips],
            self.mtu,
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Interface):
            return NotImplemented
        return (
            self.name == other.name
            and self.index == other.index
            and self.mac == other.mac
            and self.ips == other.ips
            and self.mtu == other.mtu
        )

    def __hash__(self) -> int:
        """Hash the same fields :meth:`__eq__` compares, so equal hashes equal.

        Defining ``__eq__`` without this sets ``__hash__`` to ``None``, which
        made ``set(get_interfaces())`` -- de-duplicating adapters, the obvious
        operation on the package's flagship return value -- raise
        ``TypeError``. :attr:`raw` is a dict and is left out of both.
        """
        return hash((self.name, self.index, self.mac, self.ips, self.mtu))


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


class _Pending:
    """An interface still collecting addresses.

    ``getifaddrs`` reports one list node per address and one for the MAC, so
    the fields arrive piecemeal; an :class:`Interface` cannot change after
    construction, so they are gathered here and built once.
    """

    def __init__(
        self,
        name: str,
        index: int,
        mtu: "Optional[int]",
        is_loopback: bool,
        raw: "Optional[Dict[str, Any]]",
    ) -> None:
        self.name = name
        self.index = index
        self.mtu = mtu
        self.is_loopback = is_loopback
        self.raw = raw
        self.mac: "Optional[MACAddress]" = None
        self.ips: "List[_IPInterface]" = []

    def build(self) -> Interface:
        return Interface(
            name=self.name,
            index=self.index,
            mac=self.mac,
            ips=self.ips,
            mtu=self.mtu,
            raw=self.raw,
            is_loopback=self.is_loopback,
        )


def _prefix_from_netmask(packed: bytes) -> int:
    """Count leading set bits in a packed netmask.

    Derived by counting rather than read from a field: POSIX reports the mask
    as a sockaddr, and non-contiguous masks (legal in theory, absent in
    practice) would otherwise produce nonsense. Counting stops at the first
    zero bit, which is the conservative reading.
    """
    bits = 0
    for byte in packed:
        if byte == 0xFF:
            bits += 8
            continue
        while byte & 0x80:
            bits += 1
            byte = (byte << 1) & 0xFF
        break
    return bits


def _make_ip_interface(addr: str, prefix: int) -> "Optional[_IPInterface]":
    """Build an ip_interface, returning None for anything unparseable.

    A malformed entry from the OS must never abort the whole enumeration, so
    every failure mode collapses to ``None`` for the caller to skip.
    """
    try:
        return _ipaddress.ip_interface("%s/%d" % (addr, prefix))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# POSIX: getifaddrs(3)
# ---------------------------------------------------------------------------

#: Annotated as ``Any``-valued because the two branches have different field
#: types, and ctypes' own ``_fields_`` signature is a union of several shapes.
_sockaddr_header_fields: "List[Tuple[str, Any]]"

if _HAS_SA_LEN:
    # macOS / BSD: 1-byte length, then 1-byte family.
    _sockaddr_header_fields = [("sa_len", c_uint8), ("sa_family", c_uint8)]
else:
    # Linux: 2-byte family, no length byte.
    _sockaddr_header_fields = [("sa_family", c_uint16)]


class _SockaddrHeader(Structure):
    """Just enough of ``struct sockaddr`` to read the family portably."""

    _fields_ = _sockaddr_header_fields


class _SockaddrIn(Structure):
    _fields_ = _sockaddr_header_fields + [
        ("sin_port", c_uint16),
        ("sin_addr", c_uint8 * 4),
    ]


class _SockaddrIn6(Structure):
    _fields_ = _sockaddr_header_fields + [
        ("sin6_port", c_uint16),
        ("sin6_flowinfo", c_uint32),
        ("sin6_addr", c_uint8 * 16),
        ("sin6_scope_id", c_uint32),
    ]


class _SockaddrLl(Structure):
    """Linux ``struct sockaddr_ll`` -- carries the MAC under AF_PACKET.

    Declared with the *Linux* header unconditionally rather than the host's:
    ``sockaddr_ll`` exists only on Linux, so its layout never has the BSD
    ``sa_len`` byte no matter where this module is imported. The AF_PACKET
    branch reading it is guarded by ``not _HAS_SA_LEN`` anyway, and pinning the
    layout keeps it inspectable from any platform.
    """

    _fields_ = [
        ("sll_family", c_uint16),
        ("sll_protocol", c_uint16),
        ("sll_ifindex", c_int),
        ("sll_hatype", c_uint16),
        ("sll_pkttype", c_uint8),
        ("sll_halen", c_uint8),
        ("sll_addr", c_uint8 * 8),
    ]


class _SockaddrDl(Structure):
    """macOS/BSD ``struct sockaddr_dl`` -- carries the MAC under AF_LINK.

    Declared with the *BSD* header unconditionally, for the same reason as
    :class:`_SockaddrLl`: ``sockaddr_dl`` is a BSD structure and always has the
    leading ``sdl_len`` byte.

    ``sdl_data`` is **12 bytes, as the C struct declares it** -- ``sizeof`` is
    20. It used to be declared at 46 (a 54-byte struct), which made every read
    of it a 34-byte over-read past what ``getifaddrs`` allocated. It never
    faulted, because getifaddrs hands back one contiguous arena, but it was
    undefined behaviour a page boundary could have turned into a crash.

    The structure is *variable-length*: the interface name and the hardware
    address are packed into ``sdl_data`` one after the other, and ``sdl_len``
    reports how many bytes really exist. So the address sits ``sdl_nlen`` bytes
    in -- past the declared 12 when the name is long -- and every read of it
    must be bounded by ``sdl_len`` rather than by ``sizeof``.
    """

    _fields_ = [
        ("sdl_len", c_uint8),
        ("sdl_family", c_uint8),
        ("sdl_index", c_uint16),
        ("sdl_type", c_uint8),
        ("sdl_nlen", c_uint8),
        ("sdl_alen", c_uint8),
        ("sdl_slen", c_uint8),
        ("sdl_data", c_char * 12),
    ]


def _mac_from_sockaddr_dl(sdl: "_SockaddrDl") -> "Optional[MACAddress]":
    """Extract the MAC from a BSD ``sockaddr_dl``, or ``None``.

    The address starts ``sdl_nlen`` bytes into ``sdl_data`` (the interface
    name is stored first, without a terminator), so it cannot be read at a
    fixed offset -- and it can begin past the declared end of ``sdl_data``,
    since the structure is variable-length.

    ``sdl_len`` is the bound: it is the size the kernel actually allocated, so
    anything that does not fit inside it is not ours to read. A structure whose
    ``sdl_len`` does not cover the address yields ``None`` rather than a guess.

    The read goes through the struct's own address because ``sdl.sdl_data`` is
    a ``c_char`` array, which ctypes converts to ``bytes`` on attribute access
    -- and ``addressof()`` on that copy is a ``TypeError``, not a pointer to
    the buffer.
    """
    if sdl.sdl_alen != 6:
        return None
    offset = _SockaddrDl.sdl_data.offset + sdl.sdl_nlen
    if offset + 6 > sdl.sdl_len:
        return None
    return _mac(_ctypes.string_at(_ctypes.addressof(sdl) + offset, 6))


class _Ifaddrs(Structure):
    pass


# Self-referential: ifa_next points at the same struct, so the field list can
# only be attached after the class exists.
_Ifaddrs._fields_ = [
    ("ifa_next", POINTER(_Ifaddrs)),
    ("ifa_name", c_char_p),
    ("ifa_flags", c_uint32),
    ("ifa_addr", POINTER(_SockaddrHeader)),
    ("ifa_netmask", POINTER(_SockaddrHeader)),
    ("ifa_dstaddr", POINTER(_SockaddrHeader)),
    ("ifa_data", c_void_p),
]


#: SIOCGIFMTU differs per platform: Linux has its own value, the BSDs share
#: another. Absent elsewhere, in which case MTU is simply unavailable.
_SIOCGIFMTU = 0x8921 if _sys.platform.startswith("linux") else 0xC0206933


def _posix_mtu(name: str) -> "Optional[int]":
    """Link MTU for ``name`` via ioctl, or None when unavailable.

    getifaddrs does not report MTU, so it takes a separate SIOCGIFMTU ioctl.
    Every failure mode (no fcntl, unknown request, permission) collapses to
    None -- MTU is a nice-to-have and must never break enumeration.
    """
    try:
        import fcntl
    except ImportError:
        return None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    except OSError:
        return None
    try:
        request = _struct.pack("16sI12x", name.encode("utf-8")[:15], 0)
        # typeshed marks the whole fcntl module as POSIX-only, so a Windows
        # type-check run sees no `ioctl`; the import above is what guards it.
        packed = fcntl.ioctl(  # type: ignore[attr-defined]
            sock.fileno(), _SIOCGIFMTU, request
        )
        return int(_struct.unpack("16sI12x", packed)[1]) or None
    except (OSError, ValueError, _struct.error):
        return None
    finally:
        sock.close()


def _cast_sockaddr(ptr, struct_type):
    """Reinterpret a sockaddr pointer as a more specific sockaddr struct."""
    return _ctypes.cast(ptr, POINTER(struct_type)).contents


def _posix_interfaces(want_raw: bool) -> "List[Interface]":
    """Enumerate via ``getifaddrs(3)``.

    Raises OSError if libc is unavailable or the call fails, letting
    :func:`get_interfaces` fall back.
    """
    try:
        libc = _ctypes.CDLL(None, use_errno=True)
        getifaddrs = libc.getifaddrs
        freeifaddrs = libc.freeifaddrs
    except (OSError, AttributeError) as exc:
        raise OSError("getifaddrs unavailable: %s" % (exc,))

    getifaddrs.argtypes = [POINTER(POINTER(_Ifaddrs))]
    getifaddrs.restype = c_int
    freeifaddrs.argtypes = [POINTER(_Ifaddrs)]
    freeifaddrs.restype = None

    head = POINTER(_Ifaddrs)()
    if getifaddrs(_ctypes.byref(head)) != 0:
        err = _ctypes.get_errno()
        raise OSError(err, "getifaddrs failed")

    # Keyed by name so the multiple linked-list nodes belonging to one
    # interface (one per address, plus one for the MAC) collapse into a single
    # Interface. dict preserves insertion order, so enumeration order is the
    # order the OS reported.
    found: "Dict[str, _Pending]" = {}
    try:
        node_ptr = head
        while node_ptr:
            node = node_ptr.contents
            node_ptr = node.ifa_next

            name = node.ifa_name.decode("utf-8", "replace") if node.ifa_name else ""
            if not name:
                continue

            iface = found.get(name)
            if iface is None:
                try:
                    index = _socket.if_nametoindex(name)
                except (OSError, AttributeError, ValueError):
                    index = 0
                flags = int(node.ifa_flags)
                iface = _Pending(
                    name=name,
                    index=index,
                    mtu=_posix_mtu(name),
                    # The kernel's own answer, rather than the address
                    # heuristic that stood in for it. Every node of one
                    # interface carries the same flags, so the first is enough.
                    is_loopback=bool(flags & _IFF_LOOPBACK),
                    raw={"flags": flags, "families": []} if want_raw else None,
                )
                found[name] = iface

            if not node.ifa_addr:
                continue
            family = node.ifa_addr.contents.sa_family
            if want_raw and iface.raw is not None:
                iface.raw["families"].append(family)

            if family == _socket.AF_INET:
                sa = _cast_sockaddr(node.ifa_addr, _SockaddrIn)
                addr = _socket.inet_ntop(_socket.AF_INET, bytes(sa.sin_addr))
                prefix = 32
                if node.ifa_netmask:
                    mask = _cast_sockaddr(node.ifa_netmask, _SockaddrIn)
                    prefix = _prefix_from_netmask(bytes(mask.sin_addr))
                built = _make_ip_interface(addr, prefix)
                if built is not None:
                    iface.ips.append(built)

            elif family == _socket.AF_INET6:
                sa6 = _cast_sockaddr(node.ifa_addr, _SockaddrIn6)
                addr = _socket.inet_ntop(_socket.AF_INET6, bytes(sa6.sin6_addr))
                prefix = 128
                if node.ifa_netmask:
                    mask6 = _cast_sockaddr(node.ifa_netmask, _SockaddrIn6)
                    prefix = _prefix_from_netmask(bytes(mask6.sin6_addr))
                # Link-local addresses are only meaningful with their scope.
                # ip_interface rejects the %scope suffix, so build without it
                # and note the scope in raw only.
                built = _make_ip_interface(addr, prefix)
                if built is not None:
                    iface.ips.append(built)

            elif family == _AF_PACKET and not _HAS_SA_LEN:
                sll = _cast_sockaddr(node.ifa_addr, _SockaddrLl)
                if sll.sll_halen == 6:
                    iface.mac = _mac(bytes(bytearray(sll.sll_addr)[:6]))

            elif family == _AF_LINK and _HAS_SA_LEN:
                sdl = _cast_sockaddr(node.ifa_addr, _SockaddrDl)
                mac = _mac_from_sockaddr_dl(sdl)
                if mac is not None:
                    iface.mac = mac
    finally:
        # getifaddrs allocates; skipping this leaks on every call.
        freeifaddrs(head)

    return [pending.build() for pending in found.values()]


# ---------------------------------------------------------------------------
# Windows: GetAdaptersAddresses
# ---------------------------------------------------------------------------

_MAX_ADAPTER_ADDRESS_LENGTH = 8
_ERROR_SUCCESS = 0
_ERROR_BUFFER_OVERFLOW = 111
_AF_UNSPEC = 0
# Skip anycast/multicast/DNS -- we only want unicast addresses.
_GAA_FLAG_SKIP_ANYCAST = 0x0002
_GAA_FLAG_SKIP_MULTICAST = 0x0004
_GAA_FLAG_SKIP_DNS_SERVER = 0x0008


if _IS_WINDOWS:
    from ctypes import wintypes as _wintypes

    class _SocketAddress(Structure):
        _fields_ = [("lpSockaddr", c_void_p), ("iSockaddrLength", c_int)]

    class _IpAdapterUnicastAddress(Structure):
        pass

    _IpAdapterUnicastAddress._fields_ = [
        ("Length", c_ulong),
        ("Flags", _wintypes.DWORD),
        ("Next", POINTER(_IpAdapterUnicastAddress)),
        ("Address", _SocketAddress),
        ("PrefixOrigin", c_int),
        ("SuffixOrigin", c_int),
        ("DadState", c_int),
        ("ValidLifetime", c_ulong),
        ("PreferredLifetime", c_ulong),
        ("LeaseLifetime", c_ulong),
        ("OnLinkPrefixLength", c_uint8),
    ]

    class _IpAdapterAddresses(Structure):
        pass

    _IpAdapterAddresses._fields_ = [
        ("Length", c_ulong),
        ("IfIndex", _wintypes.DWORD),
        ("Next", POINTER(_IpAdapterAddresses)),
        ("AdapterName", c_char_p),
        ("FirstUnicastAddress", POINTER(_IpAdapterUnicastAddress)),
        ("FirstAnycastAddress", c_void_p),
        ("FirstMulticastAddress", c_void_p),
        ("FirstDnsServerAddress", c_void_p),
        ("DnsSuffix", _wintypes.LPWSTR),
        ("Description", _wintypes.LPWSTR),
        ("FriendlyName", _wintypes.LPWSTR),
        ("PhysicalAddress", c_uint8 * _MAX_ADAPTER_ADDRESS_LENGTH),
        ("PhysicalAddressLength", _wintypes.DWORD),
        ("Flags", _wintypes.DWORD),
        ("Mtu", _wintypes.DWORD),
        ("IfType", _wintypes.DWORD),
        ("OperStatus", c_int),
        ("Ipv6IfIndex", _wintypes.DWORD),
        ("ZoneIndices", _wintypes.DWORD * 16),
        ("FirstPrefix", c_void_p),
    ]


def _win_sockaddr_to_str(lp_sockaddr: int) -> "Optional[str]":
    """Decode a Windows sockaddr pointer to a textual address."""
    if not lp_sockaddr:
        return None
    header = _ctypes.cast(lp_sockaddr, POINTER(_SockaddrHeader)).contents
    family = header.sa_family
    if family == _socket.AF_INET:
        sa = _ctypes.cast(lp_sockaddr, POINTER(_SockaddrIn)).contents
        return _socket.inet_ntop(_socket.AF_INET, bytes(sa.sin_addr))
    if family == _socket.AF_INET6:
        sa6 = _ctypes.cast(lp_sockaddr, POINTER(_SockaddrIn6)).contents
        return _socket.inet_ntop(_socket.AF_INET6, bytes(sa6.sin6_addr))
    return None


def _windows_interfaces(want_raw: bool) -> "List[Interface]":
    """Enumerate via ``GetAdaptersAddresses``.

    Raises OSError when the API is unavailable or keeps failing, letting
    :func:`get_interfaces` fall back.
    """
    try:
        iphlpapi = _ctypes.WinDLL("iphlpapi.dll")  # type: ignore[attr-defined]  # Windows-only name; mypy checks this branch on every platform, and it is already guarded at runtime
        get_adapters = iphlpapi.GetAdaptersAddresses
    except (OSError, AttributeError) as exc:
        raise OSError("GetAdaptersAddresses unavailable: %s" % (exc,))

    get_adapters.argtypes = [
        c_ulong,
        c_ulong,
        c_void_p,
        POINTER(_IpAdapterAddresses),
        POINTER(c_ulong),
    ]
    get_adapters.restype = c_ulong

    flags = (
        _GAA_FLAG_SKIP_ANYCAST | _GAA_FLAG_SKIP_MULTICAST | _GAA_FLAG_SKIP_DNS_SERVER
    )
    size = c_ulong(15 * 1024)  # MSDN's recommended starting size.
    buf = None

    # The required size can change between the sizing call and the real one
    # (an adapter appearing), so retry a bounded number of times rather than
    # trusting the first answer or looping forever.
    for _ in range(5):
        buf = _ctypes.create_string_buffer(size.value)
        ret = get_adapters(
            _AF_UNSPEC,
            flags,
            None,
            _ctypes.cast(buf, POINTER(_IpAdapterAddresses)),
            _ctypes.byref(size),
        )
        if ret == _ERROR_SUCCESS:
            break
        if ret != _ERROR_BUFFER_OVERFLOW:
            raise OSError(ret, "GetAdaptersAddresses failed")
    else:
        raise OSError("GetAdaptersAddresses kept reporting buffer overflow")

    interfaces: "List[Interface]" = []
    node_ptr = _ctypes.cast(buf, POINTER(_IpAdapterAddresses))
    while node_ptr:
        node = node_ptr.contents
        node_ptr = node.Next

        # FriendlyName is the human-usable name ("Ethernet"); AdapterName is
        # the GUID, which belongs in raw only.
        name = node.FriendlyName or (node.Description or "")

        mac = None
        if node.PhysicalAddressLength == 6:
            mac = _mac(bytes(bytearray(node.PhysicalAddress)[:6]))

        ips: "List[_IPInterface]" = []
        addr_ptr = node.FirstUnicastAddress
        while addr_ptr:
            entry = addr_ptr.contents
            addr_ptr = entry.Next
            text = _win_sockaddr_to_str(entry.Address.lpSockaddr)
            if text is None:
                continue
            built = _make_ip_interface(text, entry.OnLinkPrefixLength)
            if built is not None:
                ips.append(built)

        raw = None
        if want_raw:
            guid = (
                node.AdapterName.decode("ascii", "replace") if node.AdapterName else ""
            )
            raw = {
                "guid": guid,
                "friendly_name": node.FriendlyName,
                "description": node.Description,
                "if_type": int(node.IfType),
                "oper_status": int(node.OperStatus),
                "mtu": int(node.Mtu),
                "flags": int(node.Flags),
            }

        # 0xFFFFFFFF is **not** an "unknown" sentinel, which is what this used to
        # say. It is ULONG max, and it means *unbounded* -- the Windows loopback
        # pseudo-interface reports it because there is no link to constrain it.
        # Measured: that interface really does carry a 65507-octet UDP datagram,
        # the full protocol maximum, and Linux reports its own `lo` as the number
        # 65536 rather than as nothing.
        #
        # Reporting None for it therefore conflated "no limit" with "could not
        # read", and cost callers badly in the one direction that matters: a
        # caller handling None by falling back to 1500 capped loopback at 1472
        # when it can do 65507. So an unbounded MTU is clamped to the IP
        # total-length maximum, which is the real constraint and yields exactly
        # the measured 65507 through `max_udp_payload`. A genuine 0 stays None.
        mtu = int(node.Mtu)
        if mtu == 0xFFFFFFFF:
            mtu = _UNBOUNDED_MTU
        interfaces.append(
            Interface(
                name=name,
                index=int(node.IfIndex),
                mac=mac,
                ips=ips,
                mtu=mtu if mtu > 0 else None,
                # IfType is the Windows spelling of IFF_LOOPBACK.
                is_loopback=int(node.IfType) == _IF_TYPE_SOFTWARE_LOOPBACK,
                raw=raw,
            )
        )

    return interfaces


# ---------------------------------------------------------------------------
# Fallback
# ---------------------------------------------------------------------------


def _fallback_interfaces(want_raw: bool) -> "List[Interface]":
    """Last-resort enumeration via ``getaddrinfo(gethostname())``.

    **Prefixes here are fiction.** There is no portable stdlib way to learn an
    address's real prefix, so every address is reported as a host route (``/32``
    or ``/128``) under a single synthetic interface. Reached only when the
    native call is unavailable or fails; check ``iface.name == "<unknown>"`` to
    detect it.
    """
    ips: "List[_IPInterface]" = []
    seen = set()
    hostname = _socket.gethostname()
    try:
        infos = _socket.getaddrinfo(hostname, None)
    except OSError:
        infos = []
    for family, _, _, _, sockaddr in infos:
        # getaddrinfo's sockaddr is typed as a union; the first element is the
        # address text for both AF_INET and AF_INET6.
        addr = str(sockaddr[0])
        if addr in seen:
            continue
        seen.add(addr)
        if family == _socket.AF_INET:
            built = _make_ip_interface(addr, 32)
        elif family == _socket.AF_INET6:
            built = _make_ip_interface(addr.split("%")[0], 128)
        else:
            continue
        if built is not None:
            ips.append(built)

    return [
        Interface(
            name="<unknown>",
            index=0,
            mac=None,
            ips=ips,
            raw=(
                {"degraded": True, "reason": "native enumeration unavailable"}
                if want_raw
                else None
            ),
        )
    ]


def _mac(octets: bytes) -> "Optional[MACAddress]":
    """Build a MACAddress, deferring the import to avoid a circular import.

    An **all-zero** address is normalised to ``None``: Linux reports the
    loopback MAC as ``00:00:00:00:00:00`` while macOS and Windows report no
    address at all, and ``iface.mac is None`` must mean "no hardware address"
    on every platform rather than growing a per-platform branch in caller code.
    ``MACAddress(b"\\x00" * 6)`` itself stays perfectly valid -- this is a
    normalisation of what the OS reported, not a change to the type.
    """

    if not any(octets):
        return None
    try:
        return MACAddress(octets)
    except (ValueError, TypeError):
        return None


#: Default lifetime for a cached enumeration, in seconds, used by ``cache=True``.
#:
#: **One second, because this cache exists to collapse a burst of back-to-back
#: calls** -- resolving the arrival interface of every datagram in a flood, or
#: walking a list of addresses -- not to hold a long-lived snapshot. At a
#: measured 0.98 ms per enumeration that bounds the cost at one syscall per
#: second whatever the arrival rate: roughly 0.1% overhead at 1000 packets per
#: second, against a 97x saving on each individual call. A longer default would
#: buy almost nothing more and would widen the window in which the answer is
#: wrong.
#:
#: :class:`netimps.UDPEndpoint` uses this same constant for its own
#: arrival-interface cache, so there is one number rather than two that can
#: disagree. Pass a number to choose your own, and prefer ``cache=math.inf``
#: plus :func:`clear_interface_cache` when you know the moment it changes.
INTERFACE_CACHE_TTL = 1.0

_CACHE_LOCK = _threading.Lock()
#: ``raw`` flag -> (monotonic stamp, interfaces). Keyed by ``raw`` because the two
#: return different data and sharing one entry would hand a caller the wrong shape.
_INTERFACE_CACHE: "Dict[bool, Tuple[float, List[Interface]]]" = {}


def clear_interface_cache() -> None:
    """Drop any cached enumeration, so the next cached call re-enumerates.

    For a caller that *knows* the adapter set changed -- it bound a socket,
    watched netlink, or handled ``WM_NETWORKCHANGE`` -- and should not wait out
    the TTL. Harmless when nothing is cached.
    """
    with _CACHE_LOCK:
        _INTERFACE_CACHE.clear()


_ENUMERATIONS = 0


def interface_enumerations() -> int:
    """How many times this process has really enumerated its adapters.

    Monotonic, and counts only the **syscall**, never a cached hit -- which is
    the point: with ``cache=`` a lookup and an enumeration stop being the same
    event, and the enumeration is the one a packet flood multiplies. A test
    reads it either side of the code under test::

        before = interface_enumerations()
        for _ in range(20):
            get_interface(address, cache=True)
        assert interface_enumerations() - before == 1

    It is also worth exporting as a metric: how often a long-running server
    re-reads its adapters answers whether its cache is sized right.

    Both ``raw=True`` and ``raw=False`` count into this one total. The cache is
    keyed by ``raw``, so a process using both pays two enumerations to warm up
    and will see this advance twice.

    :func:`clear_interface_cache` does not advance it -- dropping a cache
    enumerates nothing by itself; the next cached call is what pays.
    """
    return _ENUMERATIONS


def _enumerate_interfaces(raw: bool) -> "List[Interface]":
    global _ENUMERATIONS

    # Counted under the cache lock rather than bare, because `+= 1` on an int is
    # not atomic and this is the one number a caller may be asserting on. The
    # lock is held for the increment only, never across the syscall below, which
    # would serialise every thread behind the slowest platform call.
    with _CACHE_LOCK:
        _ENUMERATIONS += 1

    try:
        if _IS_WINDOWS:
            return _windows_interfaces(raw)
        return _posix_interfaces(raw)
    except (OSError, AttributeError, ValueError):
        return _fallback_interfaces(raw)


def _copy_interfaces(found: "List[Interface]") -> "List[Interface]":
    """The cached interfaces as the caller's own list, with no shared dict.

    An :class:`Interface` cannot change after construction, so the stored
    objects are handed out as they are. The one exception is ``raw``, a dict a
    caller could still mutate, so an interface that carries one is rebuilt
    around a copy of it; those exist only after ``get_interfaces(raw=True)``.
    """
    return [
        (
            iface
            if iface.raw is None
            else Interface(
                name=iface.name,
                index=iface.index,
                mac=iface.mac,
                ips=iface.ips,
                mtu=iface.mtu,
                raw=dict(iface.raw),
                is_loopback=iface._is_loopback,
            )
        )
        for iface in found
    ]


def get_interfaces(
    *,
    raw: bool = False,
    cache: "Union[bool, float]" = False,
) -> "List[Interface]":
    """Return this host's network interfaces.

    Uses ``getifaddrs(3)`` on POSIX and ``GetAdaptersAddresses`` on Windows via
    :mod:`ctypes` -- no third-party dependency -- so adapter names, MACs and
    real prefix lengths are all available::

        for iface in get_interfaces():
            print(iface.name, iface.mac, [str(ip) for ip in iface.ips])

    :param raw: when True, populate :attr:`Interface.raw` with the untouched
        platform data (Linux/BSD ``flags``; Windows adapter ``guid``,
        ``if_type``, ...). **Not portable** -- outside the stability guarantee.
    :param cache: reuse a recent enumeration instead of making the syscall.
        ``False`` (the default) never caches and never reads a cached value, so
        existing behaviour is untouched. ``True`` uses
        :data:`INTERFACE_CACHE_TTL` seconds, and a number is that TTL in
        seconds -- so **``cache=0`` enumerates now and reseeds the cache**, a
        TTL of zero being always stale. That is the only "force a refresh"
        anyone needs, which is why there is no second argument for it;
        :func:`clear_interface_cache` covers invalidating without a lookup.

        The cache is process-wide and shared with
        :func:`netimps.get_interface`, :func:`netimps.iter_interfaces` and
        :func:`netimps.is_local_address`, which all take the same argument.

    **Opt-in on purpose.** Enumeration is a syscall, and on a host with many
    adapters a measured 35-42 ms of one, so a per-packet caller needs a cache;
    but an adapter set changes under you, and silently answering from a stale
    snapshot by default would turn a cheap call into a wrong one. The caller
    knows which it wants.

    **Prefer an event to a TTL when you have one.** A TTL is a guess about how
    long the answer stays true; if your program already knows the moment it can
    change, say so instead::

        get_interfaces(cache=math.inf)   # never expires on its own
        ...
        clear_interface_cache()          # at the moment it can change

    That is strictly better than any TTL: no window of wrong answers, and no
    re-enumeration while nothing has changed. A server binding its sockets has
    exactly such a moment, since binding is when the set of addresses it serves
    can change.

    A TTL (``cache=True``, or a number) is for the caller with no such moment --
    a loop making many calls in a row that just wants to stop paying for every
    one, and can tolerate :data:`INTERFACE_CACHE_TTL` of staleness.

    Enumerating per datagram is not merely slow: at 35-42 ms it is slow enough
    that a packet flood can deny service on its own.

    **A cached call returns the same immutable objects, in a fresh list.**
    ``Interface`` cannot change after construction and ``ips`` is a tuple, so
    one caller cannot corrupt another's view; only ``raw``, a dict, is copied.

    Never raises for enumeration failure: if the native call is unavailable it
    degrades to a hostname-resolution fallback in which prefixes are *not*
    real (every address becomes a ``/32``/``/128`` under an interface named
    ``"<unknown>"``). A degraded result is cached like any other -- it is the
    honest answer for as long as the native call keeps failing.
    """
    if cache is False:
        return _enumerate_interfaces(raw)

    # `is True` rather than truthiness, and the distinction carries weight:
    # `cache=1` is a one-second TTL rather than the default one, and `cache=0`
    # is "always stale" -- enumerate and store -- rather than "do not cache".
    # That last case is what a caller means by "refresh", so it needs no
    # argument of its own.
    ttl = INTERFACE_CACHE_TTL if cache is True else float(cache)
    with _CACHE_LOCK:
        entry = _INTERFACE_CACHE.get(bool(raw))
        if entry is not None and (_time.monotonic() - entry[0]) < ttl:
            return _copy_interfaces(entry[1])

    # Enumerated outside the lock: it is a syscall, and holding a lock across it
    # would serialise every thread behind the slowest platform call. Two threads
    # racing here duplicate the work once and then agree, which is cheaper than
    # the contention.
    found = _enumerate_interfaces(raw)
    with _CACHE_LOCK:
        _INTERFACE_CACHE[bool(raw)] = (_time.monotonic(), found)
    # The freshly enumerated list is already the caller's own, so it is handed
    # back directly; only a cache *hit* has to copy.
    return _copy_interfaces(found)


def is_broadcast(
    address: "Any",
    interface: "Optional[Any]" = None,
    *,
    cache: "Union[bool, float]" = False,
) -> bool:
    """Whether *address* is an IPv4 broadcast address, limited or subnet.

    The question a wildcard-bound UDP server asks about
    :attr:`netimps.Datagram.local_address` before answering: RFC 1123 says a TFTP
    server must ignore a broadcast request, and DHCP has to tell a broadcast
    DISCOVER from a unicast RENEW.

    Pass ``interface`` whenever the caller has it -- a
    :attr:`netimps.Datagram.interface`, say. Without it this enumerates every
    adapter, measured at **1.25 ms against 0.004 ms**, and a server asking the
    question of every request pays that per packet. ``cache=`` is the fallback
    for when the interface is genuinely unknown; it means what it means on
    :func:`get_interfaces`.

    ``255.255.255.255`` (limited broadcast) needs no context and short-circuits
    before any of that. The **subnet** broadcast does: ``10.0.0.255`` is only a
    broadcast if some interface carries ``10.0.0.0/24``, so this consults
    interface prefixes -- which is why it lives
    here and not in :mod:`netimps._ip`. Pass ``interface`` to check one adapter
    (the arrival interface, from ``Datagram.interface``); omit it to check every
    local one, which costs an enumeration.

    A **v4-mapped** address is unmapped first, because a dual-stack listener
    reports an IPv4 arrival as ``::ffff:a.b.c.d`` and the broadcast question is
    about the v4 address inside.

    IPv6 has **no broadcast** -- it uses multicast instead -- so a genuine v6
    address is always ``False`` here. :func:`netimps.is_multicast` is the
    companion predicate, kept separate on purpose: "do not answer this" is
    usually ``is_broadcast(a, i) or is_multicast(a)``, and one name meaning both
    would hide which of the two it matched.

    Never raises: an address it cannot parse is not a broadcast.
    """
    from ._ip import IPAddress, IPv4Address

    parsed = address if isinstance(address, (IPv4Address,)) else None
    if parsed is None:
        candidate = try_parse(str(address), IPAddress)
        if candidate is None:
            return False
        parsed = unmap(candidate)  # type: ignore[assignment]
    if not isinstance(parsed, IPv4Address):
        return False

    # The limited broadcast, which needs no interface context at all.
    if parsed == IPv4Address("255.255.255.255"):
        return True

    if interface is not None:
        candidates: "Iterable[Any]" = [interface]
    elif cache is False:
        candidates = get_interfaces()
    else:
        candidates = get_interfaces(cache=cache)
    for entry in candidates:
        for bound in getattr(entry, "ips", ()) or ():
            network = getattr(bound, "network", None)
            if network is None or network.version != 4:
                continue
            # A /31 or /32 has no broadcast address distinct from its hosts;
            # `broadcast_address` still answers, so size it out explicitly.
            if network.prefixlen >= 31:
                continue
            if parsed == network.broadcast_address:
                return True
    return False


def iter_addresses(
    interfaces: "Optional[Iterable[Interface]]" = None,
    *,
    family: "Optional[int]" = None,
) -> "Iterator[Tuple[Interface, _IPInterface]]":
    """Yield ``(interface, address)`` once per address, not once per adapter.

    :func:`get_interfaces` groups every address under its adapter, which is the
    right shape for "describe this host". Consumers that filter or act *per
    address* -- picking a bind target, excluding link-local, matching a subnet
    -- want the flattened view instead, and would otherwise write the same
    nested loop each time::

        for iface, addr in iter_addresses():
            if addr.ip in some_network:
                bind_to(addr.ip)

    :param interfaces: reuse an existing enumeration instead of calling
        :func:`get_interfaces` again. Worth passing in a loop, since
        enumeration is a syscall.
    :param family: ``4`` or ``6`` to yield only that family; ``None`` for both.
        This is the **short form**, not ``socket.AF_INET``/``AF_INET6`` --
        unlike :func:`netimps.bind` and :func:`netimps.get_free_port`, which
        take the ``AF_*`` constants. Anything else raises :class:`ValueError`
        **when this function is called**, not on the first ``next()``: a
        generator that validates lazily reports a bad argument from somewhere
        the traceback no longer names the caller.

    The ``interface`` is the full :class:`Interface`, so its name, MAC and MTU
    stay reachable -- the flattening loses no information.
    """
    if family not in (None, 4, 6):
        hint = ""
        if family == _socket.AF_INET:
            hint = " -- that is socket.AF_INET; this parameter wants 4"
        elif family == _socket.AF_INET6:
            hint = " -- that is socket.AF_INET6; this parameter wants 6"
        raise ValueError(
            "family must be 4, 6 or None (the short form, not socket.AF_INET/"
            "AF_INET6), got %r%s" % (family, hint)
        )
    return _iter_addresses(interfaces, family)


def _iter_addresses(
    interfaces: "Optional[Iterable[Interface]]",
    family: "Optional[int]",
) -> "Iterator[Tuple[Interface, _IPInterface]]":
    """The generator half of :func:`iter_addresses`, after validation."""
    if interfaces is None:
        interfaces = get_interfaces()
    for iface in interfaces:
        entries: "Sequence[_IPInterface]"
        if family == 4:
            entries = iface.ipv4
        elif family == 6:
            entries = iface.ipv6
        else:
            entries = iface.ips
        for entry in entries:
            yield iface, entry
