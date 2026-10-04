"""Readability notification for a socket, on any asyncio loop (internal).

An ``add_reader`` polyfill, and nothing more. :class:`netimps.UDPEndpoint`'s async
methods use it so that one ``recv`` path serves both loop types.

**Why this exists.** The Windows default :class:`asyncio.ProactorEventLoop` has no
``add_reader`` -- it raises :class:`NotImplementedError` -- and its
``IocpProactor.recvfrom`` discards ancillary data, which is the whole point of
``UDPEndpoint``. There is no IOCP route either: measured on 3.14, CPython's
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

    One waiter at a time -- this is a receive loop's tool, and two coroutines
    awaiting one socket would race for the same datagram however the waiting
    were arranged. A cancelled :meth:`wait` unregisters itself, so the ordinary
    shutdown (cancel the receive task, then close the socket) leaves nothing
    behind.

    **Rebinds when a different loop waits on it.** The thread path captures a
    loop for the life of its thread, so serving one endpoint from a second loop
    -- ``asyncio.run(serve())`` twice, or a server stopped and restarted --
    retires that thread and starts another rather than posting readiness to a
    closed loop.
    """

    __slots__ = (
        "_sock",
        "_thread",
        "_wake_r",
        "_wake_w",
        "_request",
        "_closed",
        "_pending",
        "_loop",
        "_stop",
    )

    def __init__(self, sock: "_socket.socket") -> None:
        self._sock = sock
        self._thread: "Optional[_threading.Thread]" = None
        #: The loop the current thread posts to. Tracked so that serving the
        #: same endpoint from a *second* loop rebinds instead of posting
        #: readiness to a closed one.
        self._loop: "Any" = None
        #: Per-thread stop flag. Distinct from `_closed`, which is permanent:
        #: rebinding has to retire one thread without closing the notifier.
        self._stop: "Optional[_threading.Event]" = None
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

        on_loop = self._try_add_reader(loop, future)
        if not on_loop:
            # Order matters: the future must be visible to the thread *before*
            # the thread is told to watch, or it can fire with nothing to resolve
            # and then wait forever for a read that never happens.
            self._pending = future
            self._ensure_thread(loop)
            self._request.set()

        try:
            await future
        finally:
            # **Cancellation must not leave the loop watching this socket.**
            # `_ready` unregisters only when it actually fires, so a task
            # cancelled while awaiting -- a server's `stop()`, the most ordinary
            # shutdown there is -- used to leave the reader registered until the
            # socket next became readable. Close the socket first, which is the
            # usual teardown order, and the loop is left polling a closed fd and
            # raises from the selector. Measured: `loop.remove_reader(fileno)`
            # after a cancelled `arecv` returned True, meaning one was still
            # there.
            #
            # Unconditional rather than only-on-cancel, because
            # `remove_reader` on an unregistered fd is a no-op returning False,
            # and that is cheaper than trying to reason about which of several
            # resolution paths got there first.
            if on_loop:
                try:
                    loop.remove_reader(self._sock.fileno())
                except (NotImplementedError, OSError, ValueError):
                    pass
            elif self._pending is future:
                # The thread path's equivalent: drop the future so a later
                # notification cannot resolve an abandoned one.
                self._pending = None

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
            if self._loop is loop:
                return
            # **A second loop, so rebind rather than post to the first.**
            # `_run` captured its loop for the life of the thread, so serving one
            # endpoint from a new loop -- `asyncio.run(serve())` twice, or a
            # server stopped and restarted -- sent readiness to a closed loop.
            # Measured: the second run timed out while the thread died with an
            # unhandled "Event loop is closed" from `call_soon_threadsafe`.
            # Previously the only reset was `close()`, which also closes the
            # socket, so there was no way to keep the endpoint and change loop.
            self._retire_thread()

        self._loop = loop
        self._stop = _threading.Event()
        self._wake_r, self._wake_w = _socketpair()
        thread = _threading.Thread(
            target=self._run,
            args=(loop, self._stop),
            name="netimps-readnotify",
            daemon=True,
        )
        self._thread = thread
        thread.start()

    def _retire_thread(self) -> None:
        """Stop the current thread without closing the notifier.

        Shares its teardown with :meth:`close`; the difference is only whether
        ``_closed`` was set first, which is what makes closing permanent and
        rebinding not.
        """
        if self._stop is not None:
            self._stop.set()
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
        self._stop = None
        self._loop = None
        for sock in (self._wake_r, self._wake_w):
            if sock is not None:
                try:
                    sock.close()
                except OSError:  # pragma: no cover
                    pass
        self._wake_r = self._wake_w = None
        # The request flag is left set by the wake above; clear it so a freshly
        # started thread does not immediately select unasked.
        self._request.clear()

    def _run(self, loop: "Any", stop: "_threading.Event") -> None:
        """Select on the socket plus the wake socket, signalling the loop."""
        wake = self._wake_r
        assert wake is not None
        while True:
            # Wait to be asked. One request, one notification -- so there is no
            # spin on a level-triggered socket and no window in which a stale
            # future could be resolved.
            self._request.wait()
            self._request.clear()
            if self._closed or stop.is_set():
                return
            try:
                ready, _, _ = _select.select([self._sock, wake], [], [])
            except (OSError, ValueError):  # the socket was closed under us
                return
            if self._closed or stop.is_set() or wake in ready:
                return
            if self._sock not in ready:
                continue
            pending = self._pending
            if pending is not None:
                try:
                    loop.call_soon_threadsafe(_resolve, pending)
                except RuntimeError:
                    # The loop closed between the select and the post. A daemon
                    # thread raising here printed an unhandled traceback to
                    # stderr and told the caller nothing; there is no one left
                    # to notify, so stopping is the whole correct response.
                    return

    def close(self) -> None:
        """Stop the thread, if there is one, and release the wake socket."""
        self._closed = True
        self._retire_thread()
        self._pending = None


def _resolve(future: "Any") -> None:
    if not future.done():
        future.set_result(None)


def _socketpair() -> "Any":
    """A connected pair for waking ``select``.

    ``socket.socketpair`` exists on Windows from 3.5 (emulated over loopback TCP),
    so no fallback is needed; wrapped only to keep the call site readable.
    """
    return _socket.socketpair()
