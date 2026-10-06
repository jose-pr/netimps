"""Enumeration through ``GetAdaptersAddresses``; the structures are defined on every platform."""

from __future__ import annotations

from ctypes import POINTER
from ctypes import Structure
from ctypes import c_char_p
from ctypes import c_int
from ctypes import c_uint8
from ctypes import c_ulong
from ctypes import c_void_p
import ctypes as _ctypes
import socket as _socket
from typing import List, Optional
from ctypes import wintypes as _wintypes
from ._model import Interface, _IPInterface, _mac, _make_ip_interface
from ._sockaddr import _SockaddrHeader, _SockaddrIn, _SockaddrIn6

#: ``IF_TYPE_SOFTWARE_LOOPBACK`` in ``IP_ADAPTER_ADDRESSES.IfType`` (IANA
#: ifType 24), the Windows spelling of the same fact.
_IF_TYPE_SOFTWARE_LOOPBACK = 24


#: What an MTU of ULONG max is reported as. The IP total-length field is 16 bits,
#: so 65535 is the largest datagram that can exist whatever the link allows --
#: making this a clamp to reality rather than an invented number. It yields
#: exactly 65507 through :func:`netimps.max_udp_payload`, which is the measured
#: largest UDP payload loopback actually delivers.
_UNBOUNDED_MTU = 65535


_MAX_ADAPTER_ADDRESS_LENGTH = 8
_ERROR_SUCCESS = 0
_ERROR_BUFFER_OVERFLOW = 111
_AF_UNSPEC = 0
# Skip anycast/multicast/DNS -- we only want unicast addresses.
_GAA_FLAG_SKIP_ANYCAST = 0x0002
_GAA_FLAG_SKIP_MULTICAST = 0x0004
_GAA_FLAG_SKIP_DNS_SERVER = 0x0008


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


#: ``IP_DAD_STATE``: the duplicate-address-detection state of an address.
#: Tentative (1) is still being checked and Duplicate (2) lost the check;
#: neither can be bound or sent from. Deprecated (3) and Preferred (4) can.
_IP_DAD_STATE_TENTATIVE = 1
_IP_DAD_STATE_DUPLICATE = 2

#: ``IF_OPER_STATUS``: Up is 1, Unknown 4. Down, testing, dormant, not present
#: and lower-layer-down are all "not usable".
_IF_OPER_STATUS_UP = 1
_IF_OPER_STATUS_UNKNOWN = 4


#: ``IP_ADAPTER_NO_MULTICAST`` in ``IP_ADAPTER_ADDRESSES.Flags``. Measured
#: 2026-10-07 on Windows 11: the Wi-Fi, Bluetooth, Hyper-V and loopback adapters
#: all report 0x1c0 to 0x1c5 and 0x181, none with this bit, so each is
#: multicast-capable.
_IP_ADAPTER_NO_MULTICAST = 0x10

#: ``IfType`` values that are point-to-point by definition (IANA ifType): PPP
#: (23), SLIP (28) and a tunnel (131). No such adapter was present on the
#: machine measured on 2026-10-07, so this is the definition and not a reading.
_POINT_TO_POINT_IF_TYPES = (23, 28, 131)


def _windows_is_multicast(flags: int) -> bool:
    return not flags & _IP_ADAPTER_NO_MULTICAST


def _windows_is_point_to_point(if_type: int) -> bool:
    return if_type in _POINT_TO_POINT_IF_TYPES


def _address_is_usable(dad_state: int) -> bool:
    """False for an address the system marks tentative or duplicate."""
    return dad_state not in (_IP_DAD_STATE_TENTATIVE, _IP_DAD_STATE_DUPLICATE)


def _windows_is_up(oper_status: int) -> "Optional[bool]":
    if oper_status == _IF_OPER_STATUS_UNKNOWN:
        return None
    return oper_status == _IF_OPER_STATUS_UP


def _windows_index(if_index: int, ipv6_if_index: int) -> int:
    """``IfIndex`` is the IPv4 index and is 0 on an adapter with IPv4 unbound."""
    return int(if_index) or int(ipv6_if_index)


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
            if not _address_is_usable(int(entry.DadState)):
                continue
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

        # 0xFFFFFFFF is **not** an "unknown" sentinel. It is ULONG max, and it
        # means *unbounded* -- the Windows loopback
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
                index=_windows_index(node.IfIndex, node.Ipv6IfIndex),
                mac=mac,
                ips=ips,
                mtu=mtu if mtu > 0 else None,
                is_up=_windows_is_up(int(node.OperStatus)),
                is_multicast=_windows_is_multicast(int(node.Flags)),
                is_point_to_point=_windows_is_point_to_point(int(node.IfType)),
                # IfType is the Windows spelling of IFF_LOOPBACK.
                is_loopback=int(node.IfType) == _IF_TYPE_SOFTWARE_LOOPBACK,
                raw=raw,
            )
        )

    return interfaces
