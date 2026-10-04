"""Enumeration through ``getifaddrs(3)``."""

from __future__ import annotations

from ctypes import POINTER
from ctypes import Structure
from ctypes import c_char
from ctypes import c_char_p
from ctypes import c_int
from ctypes import c_uint16
from ctypes import c_uint32
from ctypes import c_uint8
from ctypes import c_void_p
import ctypes as _ctypes
import socket as _socket
import struct as _struct
import sys as _sys
from typing import Dict, List, Optional
from .._mac import MACAddress
from ._model import Interface, _Pending, _mac, _make_ip_interface
from ._sockaddr import _HAS_SA_LEN, _SockaddrHeader, _SockaddrIn, _SockaddrIn6

# Link-layer families carrying the MAC. Linux uses AF_PACKET with sockaddr_ll;
# macOS/BSD use AF_LINK with sockaddr_dl. Neither constant is exposed portably
# by the socket module, hence the literals.
_AF_PACKET = 17  # Linux
_AF_LINK = 18  # macOS / BSD

#: ``IFF_LOOPBACK`` in ``ifa_flags``. Same value (8) on Linux and on the BSDs.
_IFF_LOOPBACK = 0x8
#: ``IFF_UP`` and ``IFF_RUNNING`` in ``ifa_flags``: configured up, and the link
#: has carrier. The same values (0x1, 0x40) on Linux and on the BSDs.
_IFF_UP = 0x1
_IFF_RUNNING = 0x40


def _posix_is_up(flags: int) -> bool:
    """Configured up *and* with carrier: ``IFF_UP`` and ``IFF_RUNNING``."""
    return bool(flags & _IFF_UP) and bool(flags & _IFF_RUNNING)


def _bsd_mask_bytes(sa_len: int, address_offset: int, mask: bytes) -> bytes:
    """The netmask bytes a BSD ``sockaddr`` really carries, zero-filled to width.

    macOS trims a netmask sockaddr after its last non-zero byte, and
    ``sa_len`` says how much is left: 5 for ``255.0.0.0`` (measured on macOS
    15.7: ``05 02 00 00 ff``, then the next structure), 0 for an all-zero mask.
    FreeBSD 16 sends all 16 bytes. ``address_offset`` is where the address
    bytes begin inside the sockaddr (4 for ``sockaddr_in``, 8 for
    ``sockaddr_in6``). Whatever the struct overlay read past ``sa_len`` is not
    the mask and is replaced by zero.
    """
    present = max(0, min(sa_len - address_offset, len(mask)))
    return bytes(mask[:present]) + bytes(len(mask) - present)


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
    20. Declaring it at 46 (a 54-byte struct) would make every read of it a
    34-byte over-read past what ``getifaddrs`` allocated: it would not fault,
    because getifaddrs hands back one contiguous arena, but it is undefined
    behaviour a page boundary could turn into a crash.

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
                    is_up=_posix_is_up(flags),
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
                    packed = bytes(mask.sin_addr)
                    if _HAS_SA_LEN:
                        packed = _bsd_mask_bytes(
                            node.ifa_netmask.contents.sa_len,
                            _SockaddrIn.sin_addr.offset,
                            packed,
                        )
                    prefix = _prefix_from_netmask(packed)
                built = _make_ip_interface(addr, prefix)
                if built is not None:
                    iface.ips.append(built)

            elif family == _socket.AF_INET6:
                sa6 = _cast_sockaddr(node.ifa_addr, _SockaddrIn6)
                addr = _socket.inet_ntop(_socket.AF_INET6, bytes(sa6.sin6_addr))
                prefix = 128
                if node.ifa_netmask:
                    mask6 = _cast_sockaddr(node.ifa_netmask, _SockaddrIn6)
                    packed6 = bytes(mask6.sin6_addr)
                    if _HAS_SA_LEN:
                        packed6 = _bsd_mask_bytes(
                            node.ifa_netmask.contents.sa_len,
                            _SockaddrIn6.sin6_addr.offset,
                            packed6,
                        )
                    prefix = _prefix_from_netmask(packed6)
                # Link-local addresses are only meaningful with their scope.
                # ip_interface rejects the %scope suffix, so build without it;
                # the scope is not recorded.
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
