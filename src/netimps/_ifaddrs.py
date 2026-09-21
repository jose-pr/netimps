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
import ipaddress as _ipaddress
import socket as _socket
import struct as _struct
import sys as _sys
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

__all__ = ["Interface", "get_interfaces", "iter_addresses"]

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
        mtu: Link MTU in bytes, or ``None`` when the platform does not report
            it. This is the *local link* MTU -- for a bottleneck further along
            a path see :func:`netimps.discover_mtu`.
        loopback: The kernel's own loopback flag (``IFF_LOOPBACK`` on POSIX,
            ``IF_TYPE_SOFTWARE_LOOPBACK`` on Windows), or ``None`` when it was
            not reported -- the degraded enumeration path, and objects built by
            hand. Read it through :attr:`is_loopback`, which falls back to the
            addresses when it is ``None``.
        raw: ``None`` unless enumerated with ``get_interfaces(raw=True)``, in
            which case a platform-specific dict of leftovers. **Not portable**
            and explicitly outside the stability guarantee.
    """

    __slots__ = ("name", "index", "mac", "ips", "mtu", "loopback", "raw")

    def __init__(
        self,
        name: str,
        index: int = 0,
        mac: "Optional[MACAddress]" = None,
        ips: "Optional[List[_IPInterface]]" = None,
        mtu: "Optional[int]" = None,
        raw: "Optional[Dict[str, Any]]" = None,
        loopback: "Optional[bool]" = None,
    ) -> None:
        self.name = name
        self.index = index
        self.mac = mac
        self.ips = ips if ips is not None else []
        self.mtu = mtu
        self.loopback = loopback
        self.raw = raw

    @property
    def is_loopback(self) -> bool:
        """True when this is the loopback interface.

        The kernel's own answer when there is one: ``IFF_LOOPBACK`` on POSIX,
        ``IF_TYPE_SOFTWARE_LOOPBACK`` on Windows, captured into
        :attr:`loopback` during enumeration. Never the name -- ``lo`` (Linux),
        ``lo0`` (macOS) and ``Loopback Pseudo-Interface 1`` (Windows) share no
        common spelling.

        Falls back to the addresses only when :attr:`loopback` is ``None`` (the
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
        if self.loopback is not None:
            return self.loopback
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
        ``IP_MULTICAST_IF``, a bind target and ``ping -S`` all ask. A
        **non-loopback** entry wins; a loopback one is returned only when that
        is genuinely all the interface has::

            iface.primary_ip()               # IPv4Interface('10.0.0.5/24')
            iface.primary_ip().ip            # IPv4Address('10.0.0.5')
            iface.primary_ip(ipv6=True)      # its IPv6 entry instead

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
        for entry in candidates:
            if not entry.ip.is_loopback:
                return entry
        if candidates and loopback_ok:
            return candidates[0]
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
        ``TypeError``. :attr:`ips` is a list, hence the tuple.
        """
        return hash((self.name, self.index, self.mac, tuple(self.ips), self.mtu))


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


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
    found: "Dict[str, Interface]" = {}
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
                iface = Interface(
                    name=name,
                    index=index,
                    mtu=_posix_mtu(name),
                    # The kernel's own answer, rather than the address
                    # heuristic that stood in for it. Every node of one
                    # interface carries the same flags, so the first is enough.
                    loopback=bool(flags & _IFF_LOOPBACK),
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

    return list(found.values())


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
        iphlpapi = _ctypes.WinDLL("iphlpapi.dll")
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

        # 0xFFFFFFFF is the "unknown" sentinel some adapters report.
        mtu = int(node.Mtu)
        interfaces.append(
            Interface(
                name=name,
                index=int(node.IfIndex),
                mac=mac,
                ips=ips,
                mtu=mtu if 0 < mtu < 0xFFFFFFFF else None,
                # IfType is the Windows spelling of IFF_LOOPBACK.
                loopback=int(node.IfType) == _IF_TYPE_SOFTWARE_LOOPBACK,
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
    from . import MACAddress

    if not any(octets):
        return None
    try:
        return MACAddress(octets)
    except (ValueError, TypeError):
        return None


def get_interfaces(raw: bool = False) -> "List[Interface]":
    """Return this host's network interfaces.

    Uses ``getifaddrs(3)`` on POSIX and ``GetAdaptersAddresses`` on Windows via
    :mod:`ctypes` -- no third-party dependency -- so adapter names, MACs and
    real prefix lengths are all available::

        for iface in get_interfaces():
            print(iface.name, iface.mac, [str(ip) for ip in iface.ips])

    :param raw: when True, populate :attr:`Interface.raw` with the untouched
        platform data (Linux/BSD ``flags``; Windows adapter ``guid``,
        ``if_type``, ...). **Not portable** -- outside the stability guarantee.

    Never raises for enumeration failure: if the native call is unavailable it
    degrades to a hostname-resolution fallback in which prefixes are *not*
    real (every address becomes a ``/32``/``/128`` under an interface named
    ``"<unknown>"``).
    """
    try:
        if _IS_WINDOWS:
            return _windows_interfaces(raw)
        return _posix_interfaces(raw)
    except (OSError, AttributeError, ValueError):
        return _fallback_interfaces(raw)


def iter_addresses(
    interfaces: "Optional[Iterable[Interface]]" = None,
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
