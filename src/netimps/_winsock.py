"""``recvmsg`` / ``sendmsg`` on Windows, via ``WSARecvMsg`` and ``WSASendMsg``.

CPython ships neither method on Windows, on any version -- it is not a missing
constant but a missing feature, so ``getattr(socket, ...)`` probing cannot
rescue it. Winsock does provide both, one as a documented export and one only
through a runtime-queried extension pointer, and this module binds them with
``ctypes`` so that :mod:`netimps._msg` can present a single cross-platform
call.

**This module is Windows-only and must not be imported elsewhere.** Importing
it on POSIX raises, because :class:`ctypes.WinDLL` does not exist there. Reach
it through :mod:`netimps._msg`, which imports it lazily inside its own
platform branch; that indirection is the whole reason the split exists.

Shapes match CPython's exactly -- ``recvmsg`` returns
``(data, ancdata, msg_flags, address)`` and ``sendmsg`` takes
``(buffers, ancdata, flags, address)`` -- so a caller cannot tell ours from the
native one apart from the platform it is running on. That is deliberate: the
alternative is every consumer growing its own ``if win32`` fork.

Things measured on real sockets rather than assumed, each of which contradicts
what a reader would reasonably guess from the POSIX equivalents:

- ``WSARecvMsg`` has **no export**. It is fetched per socket with
  ``WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)`` and the ``WSAID_WSARECVMSG``
  GUID. ``WSASendMsg`` *is* a plain ``ws2_32`` export.
- ``WSACMSGHDR`` is ``{SIZE_T len; INT level; INT type}``, and **both** the
  offset to a cmsg's data and the step to the next header are aligned to
  ``sizeof(void*)`` -- not to 4, and not to the header size.
- ``IN_PKTINFO`` is ``{IN_ADDR; ULONG}``: the address comes **first** and there
  is no ``spec_dst``, so it is 8 bytes against Linux's 12. ``IN6_PKTINFO``
  agrees with Linux at ``{IN6_ADDR; ULONG}``. Layouts stay native here; the
  translation table lives in :mod:`netimps._udp`.
- An empty read on a non-blocking socket surfaces as :class:`BlockingIOError`,
  because ``ctypes.WinError`` maps ``WSAEWOULDBLOCK`` through ``errno``.

``DWORD``/``ULONG`` are spelled ``c_uint32`` rather than taken from
:mod:`ctypes.wintypes` on purpose. ``import ctypes.wintypes`` fails outright on
POSIX, which would make even a guarded import of this module a hazard, and
``c_ulong`` is 32-bit on Windows but 64-bit on 64-bit Linux -- an exact width
removes both questions from the struct layouts.
"""

from __future__ import annotations

import ctypes as _ctypes
import socket as _socket
import weakref as _weakref
from typing import Any, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "recvmsg",
    "sendmsg",
    "CMSG_LEN",
    "CMSG_SPACE",
    "available",
    "set_udp_connreset",
    "SIO_UDP_CONNRESET",
]

# Windows-only names; mypy checks this module on every platform even though it
# is only ever imported on win32, so each one carries the guard explicitly.
_ws2 = _ctypes.WinDLL("ws2_32")  # type: ignore[attr-defined]

#: ``UINT_PTR``. A Windows SOCKET is a handle, not a small int as on POSIX, so
#: it must be pointer-width or the high bits are truncated on 64-bit.
_SOCKET = _ctypes.c_size_t

_DWORD = _ctypes.c_uint32
_ULONG = _ctypes.c_uint32

_SIO_GET_EXTENSION_FUNCTION_POINTER = 0xC8000006

#: Alignment for cmsg data and for the step between headers. Measured, and it
#: is pointer width rather than the 4 a reader might assume from Linux.
_ALIGN = _ctypes.sizeof(_ctypes.c_void_p)

_WSAEMSGSIZE = 10040


class _GUID(_ctypes.Structure):
    _fields_ = [
        ("Data1", _DWORD),
        ("Data2", _ctypes.c_uint16),
        ("Data3", _ctypes.c_uint16),
        ("Data4", _ctypes.c_ubyte * 8),
    ]


#: ``{F689D7C8-6F1F-436B-8A53-E54FE351C322}``
_WSAID_WSARECVMSG = _GUID(
    0xF689D7C8,
    0x6F1F,
    0x436B,
    (_ctypes.c_ubyte * 8)(0x8A, 0x53, 0xE5, 0x4F, 0xE3, 0x51, 0xC3, 0x22),
)


class _WSABUF(_ctypes.Structure):
    _fields_ = [("len", _ULONG), ("buf", _ctypes.c_void_p)]


class _WSAMSG(_ctypes.Structure):
    _fields_ = [
        ("name", _ctypes.c_void_p),
        ("namelen", _ctypes.c_int),
        ("lpBuffers", _ctypes.POINTER(_WSABUF)),
        ("dwBufferCount", _ULONG),
        ("Control", _WSABUF),
        ("dwFlags", _ULONG),
    ]


class _WSACMSGHDR(_ctypes.Structure):
    _fields_ = [
        ("cmsg_len", _ctypes.c_size_t),
        ("cmsg_level", _ctypes.c_int),
        ("cmsg_type", _ctypes.c_int),
    ]


_CMSGHDR_SIZE = _ctypes.sizeof(_WSACMSGHDR)


class _SOCKADDR_IN(_ctypes.Structure):
    _fields_ = [
        ("sin_family", _ctypes.c_ushort),
        ("sin_port", _ctypes.c_ushort),
        ("sin_addr", _ctypes.c_ubyte * 4),
        ("sin_zero", _ctypes.c_char * 8),
    ]


class _SOCKADDR_IN6(_ctypes.Structure):
    _fields_ = [
        ("sin6_family", _ctypes.c_ushort),
        ("sin6_port", _ctypes.c_ushort),
        ("sin6_flowinfo", _ULONG),
        ("sin6_addr", _ctypes.c_ubyte * 16),
        ("sin6_scope_id", _ULONG),
    ]


#: Big enough for either family plus slack, so one buffer serves both.
_SOCKADDR_STORAGE_SIZE = 128

_LPFN_WSARECVMSG = _ctypes.WINFUNCTYPE(  # type: ignore[attr-defined]
    _ctypes.c_int,
    _SOCKET,
    _ctypes.POINTER(_WSAMSG),
    _ctypes.POINTER(_DWORD),
    _ctypes.c_void_p,
    _ctypes.c_void_p,
)

_ws2.WSAIoctl.argtypes = [
    _SOCKET,
    _DWORD,
    _ctypes.c_void_p,
    _DWORD,
    _ctypes.c_void_p,
    _DWORD,
    _ctypes.POINTER(_DWORD),
    _ctypes.c_void_p,
    _ctypes.c_void_p,
]
_ws2.WSAIoctl.restype = _ctypes.c_int

#: ``WSASend`` is the scatter-gather send that works on a **stream** socket.
#: ``WSASendMsg`` does not: measured on Windows 11 build 28000, it answers
#: ``WSAEINVAL`` for a connected ``SOCK_STREAM`` while accepting a connected
#: ``SOCK_DGRAM``, so the refusal is about the socket *type* and not about
#: being connected. ``WSASend`` takes no destination and no control buffer,
#: which is exactly the buffers-only case -- see :func:`sendmsg` for the
#: dispatch.
_ws2.WSASend.argtypes = [
    _SOCKET,
    _ctypes.POINTER(_WSABUF),
    _ULONG,
    _ctypes.POINTER(_DWORD),
    _DWORD,
    _ctypes.c_void_p,
    _ctypes.c_void_p,
]
_ws2.WSASend.restype = _ctypes.c_int

_ws2.WSASendMsg.argtypes = [
    _SOCKET,
    _ctypes.POINTER(_WSAMSG),
    _DWORD,
    _ctypes.POINTER(_DWORD),
    _ctypes.c_void_p,
    _ctypes.c_void_p,
]
_ws2.WSASendMsg.restype = _ctypes.c_int

_ws2.WSAGetLastError.argtypes = []
_ws2.WSAGetLastError.restype = _ctypes.c_int


def available() -> bool:
    """Whether this module's bindings loaded.

    Always ``True`` once the module imports -- the import itself is what fails
    on a platform without ``ws2_32``. It exists so callers can express intent
    without a bare ``try: import``.
    """
    return True


def _align(n: int) -> int:
    return (n + _ALIGN - 1) & ~(_ALIGN - 1)


def CMSG_LEN(length: int) -> int:
    """Bytes a cmsg of ``length`` payload occupies, header included.

    The POSIX counterpart, for a caller sizing one ancillary item. Note the
    data offset is pointer-aligned on Windows, which is why this is not simply
    ``header + length``.
    """
    if length < 0:
        raise ValueError("length must not be negative")
    return _align(_CMSGHDR_SIZE) + length


def CMSG_SPACE(length: int) -> int:
    """Buffer space a cmsg of ``length`` payload needs, padding included.

    Use this, not :func:`CMSG_LEN`, to size a control buffer: the difference is
    the trailing pad that lets a *following* header start aligned, and
    omitting it is how a second cmsg gets silently truncated.
    """
    if length < 0:
        raise ValueError("length must not be negative")
    return _align(_CMSGHDR_SIZE) + _align(length)


def _raise_last_error() -> "Any":
    """Turn ``WSAGetLastError`` into the ``OSError`` subclass CPython would.

    ``ctypes.WinError`` resolves the Winsock code through ``errno``, so
    ``WSAEWOULDBLOCK`` arrives as :class:`BlockingIOError` and a refusal as
    :class:`ConnectionResetError` -- which is what makes this a drop-in for the
    POSIX method rather than a parallel error vocabulary.
    """
    raise _ctypes.WinError(_ws2.WSAGetLastError())  # type: ignore[attr-defined]


#: ``WSARecvMsg`` has no export and must be queried per socket. The pointer is
#: stable for a socket's life, and the query is a syscall, so it is cached
#: weakly -- a strong map would keep every socket object alive forever.
_recvmsg_fn_cache: "_weakref.WeakKeyDictionary[Any, Any]" = _weakref.WeakKeyDictionary()


def _wsarecvmsg_for(sock: "Any") -> "Any":
    fn = _recvmsg_fn_cache.get(sock)
    if fn is not None:
        return fn
    pointer = _ctypes.c_void_p()
    returned = _DWORD()
    guid = _GUID.from_buffer_copy(_WSAID_WSARECVMSG)
    rc = _ws2.WSAIoctl(
        sock.fileno(),
        _SIO_GET_EXTENSION_FUNCTION_POINTER,
        _ctypes.byref(guid),
        _ctypes.sizeof(guid),
        _ctypes.byref(pointer),
        _ctypes.sizeof(pointer),
        _ctypes.byref(returned),
        None,
        None,
    )
    if rc != 0:
        _raise_last_error()
    if not pointer.value:
        # WSAIoctl reported success but handed back NULL. Nothing documents this
        # happening; calling through it would be a hard crash rather than an
        # exception, which is worth one branch to rule out.
        raise OSError("WSAIoctl returned no WSARecvMsg pointer for this socket")
    fn = _LPFN_WSARECVMSG(pointer.value)
    try:
        _recvmsg_fn_cache[sock] = fn
    except TypeError:  # pragma: no cover - a non-weakref-able socket subclass
        pass
    return fn


def _decode_sockaddr(raw: bytes, family: int) -> "Optional[Any]":
    """Decode a raw ``sockaddr`` into the tuple ``recvfrom`` would return.

    ``AF_INET`` gives ``(host, port)``; ``AF_INET6`` gives
    ``(host, port, flowinfo, scope_id)`` -- a 4-tuple, matching CPython, so an
    IPv6 caller does not have to special-case which implementation answered.
    The port is network-order in the struct and host-order in the tuple, and
    ``flowinfo`` is masked to its 20 significant bits exactly as CPython's
    ``makesockaddr`` does.
    """
    if family == _socket.AF_INET6:
        if len(raw) < _ctypes.sizeof(_SOCKADDR_IN6):
            return None
        sa6 = _SOCKADDR_IN6.from_buffer_copy(raw[: _ctypes.sizeof(_SOCKADDR_IN6)])
        host = _socket.inet_ntop(_socket.AF_INET6, bytes(sa6.sin6_addr))
        return (
            host,
            _socket.ntohs(sa6.sin6_port),
            _socket.ntohl(sa6.sin6_flowinfo) & 0xFFFFF,
            sa6.sin6_scope_id,
        )
    if family == _socket.AF_INET:
        if len(raw) < _ctypes.sizeof(_SOCKADDR_IN):
            return None
        sa4 = _SOCKADDR_IN.from_buffer_copy(raw[: _ctypes.sizeof(_SOCKADDR_IN)])
        host = _socket.inet_ntop(_socket.AF_INET, bytes(sa4.sin_addr))
        return (host, _socket.ntohs(sa4.sin_port))
    return None


def _encode_sockaddr(address: "Any", family: int) -> "Any":
    """Build a ``sockaddr`` buffer from a CPython-style address tuple.

    Accepts the 2-tuple for ``AF_INET`` and the 2-, 3- or 4-tuple for
    ``AF_INET6``, since ``sendto`` is equally lenient about the trailing
    ``flowinfo``/``scope_id``.
    """
    if not isinstance(address, (tuple, list)) or len(address) < 2:
        raise TypeError("address must be a (host, port[, flowinfo, scope_id]) tuple")
    host = address[0]
    port = int(address[1])
    if family == _socket.AF_INET6:
        flowinfo = int(address[2]) if len(address) > 2 else 0
        scope_id = int(address[3]) if len(address) > 3 else 0
        if "%" in host:
            # A scope suffix in the host wins over a missing scope_id, so
            # "fe80::1%12" works the way it does for getaddrinfo callers.
            host, _, zone = host.partition("%")
            if not scope_id:
                scope_id = int(zone) if zone.isdigit() else _if_nametoindex(zone)
        sa6 = _SOCKADDR_IN6(
            sin6_family=_socket.AF_INET6,
            sin6_port=_socket.htons(port),
            sin6_flowinfo=_socket.htonl(flowinfo),
            sin6_scope_id=scope_id,
        )
        packed = _socket.inet_pton(_socket.AF_INET6, host)
        _ctypes.memmove(sa6.sin6_addr, packed, 16)
        return sa6
    sa4 = _SOCKADDR_IN(
        sin_family=_socket.AF_INET,
        sin_port=_socket.htons(port),
    )
    packed = _socket.inet_pton(_socket.AF_INET, host)
    _ctypes.memmove(sa4.sin_addr, packed, 4)
    return sa4


def _if_nametoindex(zone: str) -> int:
    try:
        return _socket.if_nametoindex(zone)
    except (AttributeError, OSError):
        return 0


def _parse_control(buffer: "Any", used: int) -> "List[Tuple[int, int, bytes]]":
    """Walk a control buffer into CPython's ``ancdata`` list.

    Each entry is ``(cmsg_level, cmsg_type, cmsg_data)``. A header claiming a
    length below its own size, or running past what the kernel said it wrote,
    stops the walk rather than being trusted -- a malformed buffer should yield
    fewer items, never an out-of-bounds read.
    """
    out: "List[Tuple[int, int, bytes]]" = []
    raw = bytes(buffer)
    # Never trust `used` past what was actually allocated. Winsock reports the
    # size it *wanted* in `Control.len`, not the size it wrote: a 1-byte control
    # buffer came back claiming 24, and walking that reads off the end of the
    # ctypes buffer. The caller clamps as well; this is the backstop, because an
    # out-of-bounds read is not an acceptable failure mode for a bad length.
    used = min(used, len(raw))
    offset = 0
    while offset + _CMSGHDR_SIZE <= used:
        header = _WSACMSGHDR.from_buffer_copy(raw, offset)
        length = header.cmsg_len
        if length < _CMSGHDR_SIZE or offset + length > used:
            break
        start = offset + _align(_CMSGHDR_SIZE)
        end = offset + length
        out.append((header.cmsg_level, header.cmsg_type, raw[start:end]))
        step = _align(length)
        if step <= 0:
            break
        offset += step
    return out


def _build_control(ancdata: "Iterable[Tuple[int, int, bytes]]") -> "Any":
    """Pack ``ancdata`` into a control buffer laid out as Winsock expects."""
    items = [(int(level), int(ctype), bytes(data)) for level, ctype, data in ancdata]
    if not items:
        return None
    total = sum(CMSG_SPACE(len(data)) for _, _, data in items)
    buffer = _ctypes.create_string_buffer(total)
    offset = 0
    for level, ctype, data in items:
        header = _WSACMSGHDR(
            cmsg_len=CMSG_LEN(len(data)),
            cmsg_level=level,
            cmsg_type=ctype,
        )
        _ctypes.memmove(
            _ctypes.byref(buffer, offset), _ctypes.byref(header), _CMSGHDR_SIZE
        )
        if data:
            _ctypes.memmove(
                _ctypes.byref(buffer, offset + _align(_CMSGHDR_SIZE)), data, len(data)
            )
        offset += CMSG_SPACE(len(data))
    return buffer


def recvmsg(
    sock: "Any",
    bufsize: int,
    ancbufsize: int = 0,
    flags: int = 0,
) -> "Tuple[bytes, List[Tuple[int, int, bytes]], int, Optional[Any]]":
    """``socket.recvmsg`` for Windows, via ``WSARecvMsg``.

    Returns ``(data, ancdata, msg_flags, address)``, the same 4-tuple as the
    POSIX method, with ``ancdata`` a list of ``(level, type, bytes)``.

    ``msg_flags`` carries ``MSG_CTRUNC`` when the control buffer was too small
    for everything waiting, so a caller can tell a short answer from a complete
    one. ``WSAEMSGSIZE`` -- the payload itself being truncated -- is **not** an
    error here: Winsock reports it where POSIX sets ``MSG_TRUNC``, so it is
    translated into the flag and the bytes that did arrive are returned.
    """
    if bufsize < 0:
        raise ValueError("negative buffer size")
    fn = _wsarecvmsg_for(sock)
    family = sock.family

    data = _ctypes.create_string_buffer(bufsize) if bufsize else None
    name = _ctypes.create_string_buffer(_SOCKADDR_STORAGE_SIZE)
    control = _ctypes.create_string_buffer(ancbufsize) if ancbufsize else None

    buffers = (_WSABUF * 1)()
    buffers[0].len = bufsize
    buffers[0].buf = _ctypes.cast(data, _ctypes.c_void_p) if data else None

    message = _WSAMSG(
        name=_ctypes.cast(name, _ctypes.c_void_p),
        namelen=_SOCKADDR_STORAGE_SIZE,
        lpBuffers=buffers,
        dwBufferCount=1,
        Control=_WSABUF(
            ancbufsize,
            _ctypes.cast(control, _ctypes.c_void_p) if control else None,
        ),
        dwFlags=int(flags),
    )

    received = _DWORD()
    truncated = 0
    if fn(sock.fileno(), _ctypes.byref(message), _ctypes.byref(received), None, None):
        code = _ws2.WSAGetLastError()
        if code != _WSAEMSGSIZE:
            raise _ctypes.WinError(code)  # type: ignore[attr-defined]
        # The datagram did not fit. POSIX signals that in msg_flags and hands
        # back what it read; do the same rather than raising, so a caller
        # looping on recvmsg sees one contract on both platforms.
        truncated = getattr(_socket, "MSG_TRUNC", 0) or 0x20

    payload = data.raw[: received.value] if data else b""

    # `Control.len` on return is the length Winsock *needed*, which can exceed
    # the buffer it was given -- measured at 24 against a 1-byte buffer. Treat
    # the excess as the truncation signal POSIX would have set, and parse only
    # the bytes that exist. Reading `Control.len` literally is an out-of-bounds
    # read; believing it without flagging would silently drop a cmsg.
    control_used = int(message.Control.len)
    if control_used > ancbufsize:
        truncated |= getattr(_socket, "MSG_CTRUNC", 0) or 0x200
        control_used = ancbufsize
    ancdata = _parse_control(control, control_used) if control else []

    msg_flags = int(message.dwFlags) | truncated
    return payload, ancdata, msg_flags, _decode_sockaddr(name.raw, family)


def sendmsg(
    sock: "Any",
    buffers: "Sequence[bytes]",
    ancdata: "Iterable[Tuple[int, int, bytes]]" = (),
    flags: int = 0,
    address: "Optional[Any]" = None,
) -> int:
    """``socket.sendmsg`` for Windows, via ``WSASendMsg``.

    Takes and returns exactly what the POSIX method does: an iterable of
    buffers, optional ``ancdata`` as ``(level, type, bytes)``, and the number
    of bytes sent.

    **Two Winsock calls back this, chosen by what is being sent**, because no
    single one covers the ground ``sendmsg`` does:

    - no ``ancdata`` and no ``address`` -- ``WSASend``. Required for a
      ``SOCK_STREAM`` socket, which ``WSASendMsg`` refuses outright with
      ``WSAEINVAL`` (measured on build 28000; a connected ``SOCK_DGRAM`` is
      accepted, so the refusal is about the socket type, not about being
      connected). Scatter-gather works here -- 500 buffers in one call were
      verified -- and no small ``IOV_MAX``-like cap was found.
    - otherwise -- ``WSASendMsg``, the only one that carries a control buffer
      or an explicit destination. Ancillary data on a stream socket therefore
      still fails, which is correct: Windows has no per-packet information to
      attach to one.

    Pinning the source address through an ``IP_PKTINFO`` / ``IPV6_PKTINFO``
    cmsg works here, with one trap that is **not** shared with Linux: Windows
    sends a zero address *literally* rather than reading it as "kernel
    chooses", so a pin of ``0.0.0.0`` arrives from ``0.0.0.0``. Callers must
    not pack a zero address on this platform; :mod:`netimps._udp` is where that
    rule is enforced.
    """
    if isinstance(buffers, (bytes, bytearray, memoryview)):
        raise TypeError("buffers must be a sequence of bytes-like objects, not bytes")
    chunks = [bytes(b) for b in buffers]
    if not chunks:
        chunks = [b""]

    array = (_WSABUF * len(chunks))()
    # The buffers must outlive the call; create_string_buffer copies, so each
    # one is held in this list rather than left to the garbage collector.
    keepalive = []
    for index, chunk in enumerate(chunks):
        held = _ctypes.create_string_buffer(chunk, len(chunk)) if chunk else None
        keepalive.append(held)
        array[index].len = len(chunk)
        array[index].buf = _ctypes.cast(held, _ctypes.c_void_p) if held else None

    control = _build_control(ancdata)

    if control is None and address is None:
        # Buffers only, to a connected socket: WSASend. This is the only route
        # that works on a stream socket, and it is equally correct for a
        # connected datagram one, so there is no need to inspect the type.
        sent = _DWORD()
        rc = _ws2.WSASend(
            sock.fileno(),
            array,
            len(chunks),
            _ctypes.byref(sent),
            int(flags),
            None,
            None,
        )
        if rc != 0:
            _raise_last_error()
        del keepalive
        return sent.value

    sockaddr = None
    if address is not None:
        sockaddr = _encode_sockaddr(address, sock.family)

    message = _WSAMSG(
        name=(
            _ctypes.cast(_ctypes.byref(sockaddr), _ctypes.c_void_p)
            if sockaddr is not None
            else None
        ),
        namelen=_ctypes.sizeof(sockaddr) if sockaddr is not None else 0,
        lpBuffers=array,
        dwBufferCount=len(chunks),
        Control=_WSABUF(
            _ctypes.sizeof(control) if control is not None else 0,
            _ctypes.cast(control, _ctypes.c_void_p) if control is not None else None,
        ),
        dwFlags=0,
    )

    sent = _DWORD()
    rc = _ws2.WSASendMsg(
        sock.fileno(),
        _ctypes.byref(message),
        int(flags),
        _ctypes.byref(sent),
        None,
        None,
    )
    if rc != 0:
        _raise_last_error()
    del keepalive  # explicit: the buffers were live for the duration of the call
    return sent.value


#: ``SIO_UDP_CONNRESET`` = ``_WSAIOW(IOC_VENDOR, 12)`` =
#: ``IOC_IN | IOC_VENDOR | 12``. Computed here rather than imported because
#: **CPython exports no such constant on any version**, and even given the right
#: number ``socket.ioctl`` refuses it: that method whitelists a handful of
#: commands (``SIO_RCVALL``, ``SIO_KEEPALIVE_VALS``, ``SIO_LOOPBACK_FAST_PATH``)
#: and raises ``ValueError: invalid ioctl command`` for anything else. So there is
#: no stdlib route to this behaviour at all, and ``WSAIoctl`` is the only way.
_IOC_IN = 0x80000000
_IOC_VENDOR = 0x18000000
SIO_UDP_CONNRESET = _IOC_IN | _IOC_VENDOR | 12


def set_udp_connreset(sock: "Any", enabled: bool) -> None:
    """Turn ``SIO_UDP_CONNRESET`` on or off for *sock*.

    With it off, Windows stops reporting an ICMP port-unreachable provoked by an
    earlier send as ``ConnectionResetError`` on a later, unrelated receive.

    Raises ``OSError`` if Winsock refuses -- the caller decides whether that
    matters, since this is an adjustment to behaviour rather than a correctness
    requirement.
    """
    value = _ctypes.c_ulong(1 if enabled else 0)
    returned = _DWORD()
    rc = _ws2.WSAIoctl(
        sock.fileno(),
        SIO_UDP_CONNRESET,
        _ctypes.byref(value),
        _ctypes.sizeof(value),
        None,
        0,
        _ctypes.byref(returned),
        None,
        None,
    )
    if rc != 0:
        _raise_last_error()
