"""Socket options applied after creation: the UDP connreset switch and buffer sizes."""

from __future__ import annotations

import logging as _logging
import socket as _socket
import sys as _sys
import weakref as _weakref
from typing import Optional, Tuple

_log = _logging.getLogger("netimps._sockets")


def disable_connreset(sock: "_socket.socket") -> bool:
    """Stop Windows reporting an ICMP port-unreachable on a *later* receive.

    Returns whether anything was changed -- ``False`` off Windows, where there
    is nothing to change.

    **The behaviour this turns off.** On Windows an unconnected UDP socket that
    provoked an ICMP port-unreachable gets it delivered as
    :class:`ConnectionResetError` from a subsequent ``recvfrom`` -- one that may
    have nothing to do with the peer that refused. A receive loop then dies on a
    packet some unrelated host did not want. POSIX reports asynchronous ICMP
    errors only on *connected* sockets, so this whole class of surprise does not
    arise there.

    This is the inverse face of a rule this package documents from the other
    side: an unconnected POSIX probe never *sees* a port-unreachable, which is
    why :class:`netimps.UDPEndpoint`'s MTU probing connects.

    **Not applied to a socket you did not ask for.** The report is occasionally
    what a caller wants -- a client talking to one peer learns the peer is gone
    -- so this is a call, not a hidden side effect. :func:`bind` makes it for a
    datagram socket by default, which is what a server loop wants; pass
    ``bind(..., connreset=True)`` to keep the report, or call this on a socket
    from elsewhere.

    **There is no stdlib route to this.** Measured on 3.14: CPython exports no
    ``socket.SIO_UDP_CONNRESET`` on any version, and even given the documented
    value (``0x9800000C``) ``socket.ioctl`` refuses it -- that method whitelists
    a handful of commands and answers ``ValueError: invalid ioctl command`` for
    the rest. So this goes through ``WSAIoctl`` by ``ctypes``. The ``getattr``
    route is the trap: it compiles, runs, and is a **silent no-op on every
    platform**, which is why this lives here once rather than being rewritten
    per caller.

    Best effort: a kernel or socket type that refuses the request leaves the
    socket as it was rather than raising, since this is an adjustment to
    behaviour and never a correctness requirement.
    """
    if _sys.platform != "win32":
        return False
    try:
        from .. import _winsock
    except Exception:  # pragma: no cover - a Windows without ws2_32
        return False
    try:
        _winsock.set_udp_connreset(sock, False)
    except (OSError, AttributeError, ValueError):
        return False
    return True


def set_buffer_size(
    sock: "_socket.socket",
    *,
    receive: "Optional[int]" = None,
    send: "Optional[int]" = None,
) -> "Tuple[int, int]":
    """Grow ``SO_RCVBUF``/``SO_SNDBUF``, and report what was actually granted.

    Returns ``(receive, send)`` as **read back** from the socket, never as
    requested::

        got_rx, got_tx = set_buffer_size(sock, receive=4 << 20)
        if got_rx < 4 << 20:
            log.warning("kernel granted %d of 4 MiB", got_rx)

    The default UDP buffers are small -- 64 KiB on Windows -- so a burst of
    large datagrams overruns them and the tail is dropped, which at the protocol
    level looks like loss and costs a timeout per window. Raising them is the
    fix; knowing whether the raise *took* is the part that gets skipped.

    **The kernel is not obliged to agree, and does not say so.** ``setsockopt``
    succeeds and then grants less, capped by ``net.core.rmem_max`` on Linux, and
    Linux also *doubles* what is asked for its own bookkeeping, so a read-back
    larger than the request is normal there and not a bug. Returning the
    read-back is the whole point: a silent partial grant is the failure mode.

    Only grows, never shrinks: a value already at or above the request is left
    alone, so this cannot undo a caller's earlier tuning. ``None`` skips a
    direction. A refused option is skipped rather than raised, and the
    corresponding return value is whatever the socket reports.

    A shortfall is logged once per socket, at ``WARNING`` on this module's
    logger (``netimps._sockets``); the package installs no handler.
    """
    for option, wanted in (
        (_socket.SO_RCVBUF, receive),
        (_socket.SO_SNDBUF, send),
    ):
        if wanted is None:
            continue
        if wanted < 0:
            raise ValueError("buffer size must not be negative, got %r" % (wanted,))
        try:
            if sock.getsockopt(_socket.SOL_SOCKET, option) < wanted:
                sock.setsockopt(_socket.SOL_SOCKET, option, wanted)
        except OSError:
            pass  # refused by this kernel or socket type -- report what it has

    def _current(option: int) -> int:
        try:
            return int(sock.getsockopt(_socket.SOL_SOCKET, option))
        except OSError:  # pragma: no cover - a socket that reports neither
            return 0

    granted = (_current(_socket.SO_RCVBUF), _current(_socket.SO_SNDBUF))
    short = [
        "%s: asked for %d bytes, granted %d" % (name, wanted, got)
        for name, wanted, got in (
            ("SO_RCVBUF", receive, granted[0]),
            ("SO_SNDBUF", send, granted[1]),
        )
        if wanted is not None and got < wanted
    ]
    if short and sock not in _warned_short:
        _warned_short.add(sock)
        _log.warning("socket buffer smaller than requested (%s)", "; ".join(short))
    return granted


#: Sockets already warned about, so a retry loop logs one shortfall, not one per
#: attempt. Weak: it must not keep a closed socket alive.
_warned_short: "_weakref.WeakSet[_socket.socket]" = _weakref.WeakSet()
