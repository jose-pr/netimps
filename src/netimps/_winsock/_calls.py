"""``recvmsg`` and ``sendmsg`` over ``WSARecvMsg``, ``WSASendMsg``, ``WSARecv`` and ``WSASend``."""

from __future__ import annotations

import ctypes as _ctypes
import select as _select
import socket as _socket
import time as _time
import weakref as _weakref
from typing import Any, Iterable, List, Optional, Sequence, Tuple

from ._abi import (
    _DWORD,
    _GUID,
    _LPFN_WSARECVMSG,
    _SIO_GET_EXTENSION_FUNCTION_POINTER,
    _SOCKADDR_STORAGE_SIZE,
    _WSABUF,
    _WSAEMSGSIZE,
    _WSAEWOULDBLOCK,
    _WSAID_WSARECVMSG,
    _WSAMSG,
    _raise_last_error,
    _ws2,
)
from ._cmsg import _build_control, _parse_control
from ._sockaddr import _decode_sockaddr, _encode_sockaddr

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


def _deadline(sock: "Any") -> "Optional[float]":
    """When a call on ``sock`` must give up, or ``None`` if its timeout needs no help.

    A socket with a positive timeout is non-blocking underneath: CPython's own
    methods wait for readiness and then call. A bare Winsock call on it returns
    ``WSAEWOULDBLOCK`` at once, so the wait has to be done here. A blocking
    socket (``None``) and a non-blocking one (``0``) already behave as asked.
    """
    timeout = sock.gettimeout()
    return _time.monotonic() + timeout if timeout else None


def _wait(sock: "Any", deadline: "Optional[float]", writing: bool = False) -> None:
    """Block until ``sock`` is ready or ``deadline`` passes; no-op without one.

    Raises ``socket.timeout``, which is what the stdlib method raises (and is
    the builtin :class:`TimeoutError` from Python 3.10).
    """
    if deadline is None:
        return
    remaining = deadline - _time.monotonic()
    if remaining > 0:
        readers, writers = ([], [sock]) if writing else ([sock], [])
        ready = _select.select(readers, writers, [], remaining)
        if ready[0] or ready[1]:
            return
    raise _socket.timeout("timed out")


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
    if sock.type == _socket.SOCK_STREAM:
        return _recv_stream(sock, bufsize, int(flags))
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
    deadline = _deadline(sock)
    while True:
        _wait(sock, deadline)
        if not fn(
            sock.fileno(), _ctypes.byref(message), _ctypes.byref(received), None, None
        ):
            break
        code = _ws2.WSAGetLastError()
        if code == _WSAEMSGSIZE:
            # The datagram did not fit. POSIX signals that in msg_flags and
            # hands back what it read; do the same rather than raising, so a
            # caller looping on recvmsg sees one contract on both platforms.
            truncated = getattr(_socket, "MSG_TRUNC", 0) or 0x20
            break
        if code != _WSAEWOULDBLOCK or deadline is None:
            raise _ctypes.WinError(code)  # type: ignore[attr-defined]
        # Readable a moment ago and empty now: another reader took the
        # datagram. Wait again for what is left of the timeout, with the
        # in/out fields put back as the call expects to find them.
        message.namelen = _SOCKADDR_STORAGE_SIZE
        message.Control.len = ancbufsize
        message.dwFlags = int(flags)

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


def _recv_stream(
    sock: "Any", bufsize: int, flags: int
) -> "Tuple[bytes, List[Tuple[int, int, bytes]], int, Optional[Any]]":
    """:func:`recvmsg` on a stream socket: ``WSARecv``, with no ancillary data.

    A stream carries none on Windows, and its peer is not reported per read, so
    the list is empty and the address ``None``, as for a connected stream on
    POSIX.
    """
    data = _ctypes.create_string_buffer(bufsize) if bufsize else None
    buffers = (_WSABUF * 1)()
    buffers[0].len = bufsize
    buffers[0].buf = _ctypes.cast(data, _ctypes.c_void_p) if data else None
    received = _DWORD()
    deadline = _deadline(sock)
    while True:
        _wait(sock, deadline)
        c_flags = _DWORD(flags)
        rc = _ws2.WSARecv(
            sock.fileno(),
            buffers,
            1,
            _ctypes.byref(received),
            _ctypes.byref(c_flags),
            None,
            None,
        )
        if rc == 0:
            break
        code = _ws2.WSAGetLastError()
        if code != _WSAEWOULDBLOCK or deadline is None:
            raise _ctypes.WinError(code)  # type: ignore[attr-defined]
    payload = data.raw[: received.value] if data else b""
    return payload, [], int(c_flags.value), None


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
    _wait(sock, _deadline(sock), writing=True)

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
