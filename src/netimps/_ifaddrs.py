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
Prefix source        netmask sockaddr    netmask sockaddr    ``OnLinkPrefixLength``
Link-layer family    ``AF_PACKET`` (17)  ``AF_LINK`` (18)    ``PhysicalAddress``
IPv6 scope           ``%1``              ``%en0``            ``%12``
Loopback name        ``lo``              ``lo0``             ``Loopback Pseudo-Interface 1``
===================  ==================  ==================  =================

Two consequences worth stating outright, because getting them wrong is subtle:

* ``Interface.is_loopback`` is derived from the *addresses*, never the name --
  a ``name == "lo"`` test silently fails on macOS (``lo0``) and is meaningless
  on Windows.
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
from typing import Any, Dict, List, Optional, Union

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


class Interface:
    """One network interface, normalised to be identical across platforms.

    Attributes:
        name: Human-usable adapter name (``"eth0"``, ``"en0"``, or the Windows
            *friendly* name -- never the raw GUID).
        index: :func:`socket.if_nametoindex` value, or ``0`` when unknown.
        mac: The hardware address, or ``None`` for interfaces without one
            (loopback, tunnels).
        ips: Every address bound to the interface, each as an
            ``IPv4Interface``/``IPv6Interface`` carrying its real prefix.
        mtu: Link MTU in bytes, or ``None`` when the platform does not report
            it. This is the *local link* MTU -- for a bottleneck further along
            a path see :func:`netimps.path_mtu`.
        raw: ``None`` unless enumerated with ``get_interfaces(raw=True)``, in
            which case a platform-specific dict of leftovers. **Not portable**
            and explicitly outside the stability guarantee.
    """

    __slots__ = ("name", "index", "mac", "ips", "mtu", "raw")

    def __init__(
        self,
        name: str,
        index: int = 0,
        mac: "Optional[Any]" = None,
        ips: "Optional[List[_IPInterface]]" = None,
        mtu: "Optional[int]" = None,
        raw: "Optional[Dict[str, Any]]" = None,
    ) -> None:
        self.name = name
        self.index = index
        self.mac = mac
        self.ips = ips if ips is not None else []
        self.mtu = mtu
        self.raw = raw

    @property
    def is_loopback(self) -> bool:
        """True when every address is a loopback address.

        Derived from the addresses rather than the name: ``lo`` (Linux),
        ``lo0`` (macOS) and ``Loopback Pseudo-Interface 1`` (Windows) share no
        common spelling, but ``127.0.0.0/8`` and ``::1`` do.
        """
        return bool(self.ips) and all(ip.ip.is_loopback for ip in self.ips)

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
    """Linux ``struct sockaddr_ll`` -- carries the MAC under AF_PACKET."""

    _fields_ = _sockaddr_header_fields + [
        ("sll_protocol", c_uint16),
        ("sll_ifindex", c_int),
        ("sll_hatype", c_uint16),
        ("sll_pkttype", c_uint8),
        ("sll_halen", c_uint8),
        ("sll_addr", c_uint8 * 8),
    ]


class _SockaddrDl(Structure):
    """macOS/BSD ``struct sockaddr_dl`` -- carries the MAC under AF_LINK.

    The address sits ``sdl_nlen`` bytes into ``sdl_data`` (the interface name
    is stored first, without a terminator), so it cannot be read at a fixed
    offset.
    """

    _fields_ = _sockaddr_header_fields + [
        ("sdl_index", c_uint16),
        ("sdl_type", c_uint8),
        ("sdl_nlen", c_uint8),
        ("sdl_alen", c_uint8),
        ("sdl_slen", c_uint8),
        ("sdl_data", c_char * 46),
    ]


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
        packed = fcntl.ioctl(sock.fileno(), _SIOCGIFMTU, request)
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
                iface = Interface(
                    name=name,
                    index=index,
                    mtu=_posix_mtu(name),
                    raw={"flags": node.ifa_flags, "families": []} if want_raw else None,
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
                if sdl.sdl_alen == 6:
                    # The MAC follows the interface name inside sdl_data.
                    raw_data = bytes(
                        bytearray(
                            _ctypes.string_at(_ctypes.addressof(sdl.sdl_data), 46)
                        )
                    )
                    start = sdl.sdl_nlen
                    iface.mac = _mac(raw_data[start : start + 6])
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
        addr = sockaddr[0]
        if addr in seen:
            continue
        seen.add(addr)
        if family == _socket.AF_INET:
            built = _make_ip_interface(addr, 32)
        elif family == _socket.AF_INET6:
            built = _make_ip_interface(str(addr).split("%")[0], 128)
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


def _mac(octets: bytes):
    """Build a MACAddress, deferring the import to avoid a circular import."""
    from . import MACAddress

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


def iter_addresses(interfaces=None, family=None):
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

    The ``interface`` is the full :class:`Interface`, so its name, MAC and MTU
    stay reachable -- the flattening loses no information.
    """
    if interfaces is None:
        interfaces = get_interfaces()
    for iface in interfaces:
        if family == 4:
            entries = iface.ipv4
        elif family == 6:
            entries = iface.ipv6
        elif family is None:
            entries = iface.ips
        else:
            raise ValueError("family must be 4, 6 or None, got %r" % (family,))
        for entry in entries:
            yield iface, entry
