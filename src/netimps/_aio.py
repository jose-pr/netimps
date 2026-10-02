"""Readability notification for a socket, on any asyncio loop (internal).

An ``add_reader`` polyfill, and nothing more. :class:`netimps.UdpEndpoint`'s async
methods use it so that one ``recv`` path serves both loop types.

**Why this exists.** The Windows default :class:`asyncio.ProactorEventLoop` has no
``add_reader`` -- it raises :class:`NotImplementedError` -- and its
``IocpProactor.recvfrom`` discards ancillary data, which is the whole point of
``UdpEndpoint``. There is no IOCP route either: measured on 3.14, CPython's
``_overlapped`` module exposes no ``WSARecvMsg``, so posting one through the loop's
own completion port would mean reimplementing the overlapped plumbing *and*
calling the private ``IocpProactor._register``.

So on a Proactor loop a thread does the waiting. The design point worth keeping:
**the thread reports readability and never reads**. The ``recv`` stays on the loop,
which keeps ``bufsize`` a per-call argument -- a thread that called ``recv``
itself would have to fix ``bufsize`` when it started, silently changing truncation
behaviour for a caller who passed a smaller one.

``asyncio`` is imported lazily by the caller, not at package import time: pulling
it into ``netimps/__init__`` would force the import ordering that produced the
``os.sysconf`` crash, and make an async dependency mandatory for consumers that
are only using value types.
"""

from __future__ import annotations

import select as _select
import socket as _socket
import sys as _sys
import threading as _threading
from typing import Any, Optional

__all__ = ["ReadNotifier"]

#: Proactor is the Windows default, so the thread path is the common one there
#: rather than an exotic fallback.
_MAY_LACK_ADD_READER = _sys.platform == "win32"


class ReadNotifier:
    """Tell an asyncio loop when *sock* becomes readable.

    One per endpoint, created on first use. :meth:`wait` returns an awaitable
    that resolves when the socket has data; the caller then reads it on the loop
    and the notifier re-arms.

    Not thread-safe across loops: an instance belongs to the first loop that
    waits on it, which matches an endpoint being served by one loop.
    """

    __slots__ = (
        "_sock",
        "_thread",
        "_wake_r",
        "_wake_w",
        "_request",
        "_closed",
        "_pending",
    )

    def __init__(self, sock: "_socket.socket") -> None:
        self._sock = sock
        self._thread: "Optional[_threading.Thread]" = None
        self._wake_r: "Optional[_socket.socket]" = None
        self._wake_w: "Optional[_socket.socket]" = None
        #: Set by the loop when it wants one notification. The thread selects
        #: **only** when this is set, which is what makes the handoff race-free:
        #: it cannot fire before a future exists to resolve, and it cannot fire
        #: again on a stale one. It also removes any need to care that `select`
        #: is level-triggered, since the thread does not loop back into it
        #: unasked.
        self._request = _threading.Event()
        self._closed = False
        #: The future the selector thread should resolve next. One waiter at a
        #: time, which is what a single receive loop does.
        self._pending: "Any" = None

    async def wait(self) -> None:
        """Resolve once the socket is readable. Raises if the notifier is closed."""
        import asyncio

        if self._closed:
            raise RuntimeError("notifier is closed")
        loop = asyncio.get_running_loop()
        future: "Any" = loop.create_future()

        if not self._try_add_reader(loop, future):
            # Order matters: the future must be visible to the thread *before*
            # the thread is told to watch, or it can fire with nothing to resolve
            # and then wait forever for a read that never happens.
            self._pending = future
            self._ensure_thread(loop)
            self._request.set()

        await future

    def _try_add_reader(self, loop: "Any", future: "Any") -> bool:
        """Register with the loop directly. ``False`` if it cannot do that."""
        fileno = self._sock.fileno()

        def _ready() -> None:
            try:
                loop.remove_reader(fileno)
            except (NotImplementedError, OSError):  # pragma: no cover
                pass
            if not future.done():
                future.set_result(None)

        try:
            loop.add_reader(fileno, _ready)
        except NotImplementedError:
            # The Windows Proactor loop. Not an error and not rare -- it is the
            # default there.
            return False
        return True

    def _ensure_thread(self, loop: "Any") -> None:
        if self._thread is not None:
            return
        self._wake_r, self._wake_w = _socketpair()
        thread = _threading.Thread(
            target=self._run,
            args=(loop,),
            name="netimps-readnotify",
            daemon=True,
        )
        self._thread = thread
        thread.start()

    def _run(self, loop: "Any") -> None:
        """Select on the socket plus the wake socket, signalling the loop."""
        wake = self._wake_r
        assert wake is not None
        while True:
            # Wait to be asked. One request, one notification -- so there is no
            # spin on a level-triggered socket and no window in which a stale
            # future could be resolved.
            self._request.wait()
            self._request.clear()
            if self._closed:
                return
            try:
                ready, _, _ = _select.select([self._sock, wake], [], [])
            except (OSError, ValueError):  # the socket was closed under us
                return
            if self._closed or wake in ready:
                return
            if self._sock not in ready:
                continue
            pending = self._pending
            if pending is not None:
                loop.call_soon_threadsafe(_resolve, pending)

    def close(self) -> None:
        """Stop the thread, if there is one, and release the wake socket."""
        self._closed = True
        # Both, because the thread may be blocked in either place: `_request`
        # releases it if it is waiting to be asked, and the wake socket breaks
        # `select` if it is already watching.
        self._request.set()
        if self._wake_w is not None:
            try:
                self._wake_w.send(b"\0")
            except OSError:  # pragma: no cover - already torn down
                pass
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=5.0)
        self._thread = None
        for sock in (self._wake_r, self._wake_w):
            if sock is not None:
                try:
                    sock.close()
                except OSError:  # pragma: no cover
                    pass
        self._wake_r = self._wake_w = None


def _resolve(future: "Any") -> None:
    if not future.done():
        future.set_result(None)


def _socketpair() -> "Any":
    """A connected pair for waking ``select``.

    ``socket.socketpair`` exists on Windows from 3.5 (emulated over loopback TCP),
    so no fallback is needed; wrapped only to keep the call site readable.
    """
    return _socket.socketpair()
