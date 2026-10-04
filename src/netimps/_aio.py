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
import time as _time
from typing import Any, Optional

__all__ = ["ReadNotifier", "wait_writable"]

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
    behind. :meth:`close` and :meth:`aclose` unregister the reader of a wait in
    progress and fail it with :class:`RuntimeError`, whichever order the task is
    cancelled and the endpoint closed in.

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
        "_waiter",
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
        #: ``(loop, future, descriptor, on_loop)`` of the wait in progress. The
        #: descriptor is the one registered, kept because the socket's own
        #: ``fileno()`` is -1 once it is closed.
        self._waiter: "Any" = None

    async def wait(self) -> None:
        """Resolve once the socket is readable. Raises if the notifier is closed."""
        import asyncio

        if self._closed:
            raise RuntimeError("notifier is closed")
        loop = asyncio.get_running_loop()
        future: "Any" = loop.create_future()

        fileno = self._sock.fileno()
        on_loop = self._try_add_reader(loop, future, fileno)
        self._waiter = (loop, future, fileno, on_loop)
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
            # Cancellation must not leave the loop watching this socket, and the
            # reader goes by the descriptor it was registered under: the socket
            # may already be closed, and its own `fileno()` is then -1.
            # `remove_reader` on an unregistered descriptor is a no-op.
            if self._waiter is not None and self._waiter[1] is future:
                self._waiter = None
            if on_loop:
                _remove_reader(loop, fileno)
            elif self._pending is future:
                # The thread path's equivalent: drop the future so a later
                # notification cannot resolve an abandoned one.
                self._pending = None

    def _abort_waiter(self) -> None:
        """End the wait in progress, if any, with a ``RuntimeError``.

        Called by :meth:`close` and :meth:`aclose` before the socket goes, so the
        reader is gone while its descriptor is still valid and the task awaiting
        it is woken instead of left pending.
        """
        waiter, self._waiter = self._waiter, None
        if waiter is None:
            return
        loop, future, fileno, on_loop = waiter

        def abort() -> None:
            if on_loop:
                _remove_reader(loop, fileno)
            if not future.done():
                future.set_exception(RuntimeError("endpoint is closed"))

        try:
            import asyncio

            same_thread = asyncio._get_running_loop() is loop
        except Exception:  # pragma: no cover - asyncio is imported by `wait`
            same_thread = False
        if same_thread:
            abort()
            return
        try:
            loop.call_soon_threadsafe(abort)
        except RuntimeError:  # the loop is closed: nothing is waiting on it
            pass

    def _try_add_reader(self, loop: "Any", future: "Any", fileno: int) -> bool:
        """Register with the loop directly. ``False`` if it cannot do that."""

        def _ready() -> None:
            _remove_reader(loop, fileno)
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
        thread = self._signal_stop()
        if thread is not None and thread.is_alive():
            thread.join(timeout=5.0)
        self._release()

    def _signal_stop(self) -> "Optional[_threading.Thread]":
        """Tell the thread to leave, without waiting for it. Returns the thread."""
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
        return self._thread

    def _release(self) -> None:
        """Drop the stopped thread's state and close the wake sockets."""
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
        """Stop the thread, if there is one, and release the wake socket.

        Complete on return, and harmless when called again. It blocks the
        caller until the thread has left, so from a coroutine use
        :meth:`aclose`.
        """
        self._closed = True
        self._abort_waiter()
        self._retire_thread()
        self._pending = None

    async def aclose(self) -> None:
        """:meth:`close`, without blocking the loop while the thread leaves."""
        import asyncio

        self._closed = True
        self._abort_waiter()
        thread = self._signal_stop()
        deadline = _time.monotonic() + 5.0
        while thread is not None and thread.is_alive() and _time.monotonic() < deadline:
            await asyncio.sleep(0.001)
        self._release()
        self._pending = None


async def wait_writable(sock: "_socket.socket") -> None:
    """Resolve once *sock* can accept a datagram.

    ``add_writer`` where the loop has it. The Proactor loop has none, and a
    full send buffer is the rare case, so there the socket is polled every
    5 ms with the loop free in between.
    """
    import asyncio

    loop = asyncio.get_running_loop()
    fileno = sock.fileno()
    future: "Any" = loop.create_future()

    def ready() -> None:
        if not future.done():
            future.set_result(None)

    try:
        loop.add_writer(fileno, ready)
    except NotImplementedError:
        while not _select.select([], [sock], [], 0)[1]:
            await asyncio.sleep(0.005)
        return
    try:
        await future
    finally:
        try:
            loop.remove_writer(fileno)
        except (NotImplementedError, OSError, ValueError):
            pass


def _remove_reader(loop: "Any", fileno: int) -> None:
    try:
        loop.remove_reader(fileno)
    except (NotImplementedError, OSError, ValueError):
        pass


def _resolve(future: "Any") -> None:
    if not future.done():
        future.set_result(None)


def _socketpair() -> "Any":
    """A connected pair for waking ``select``.

    ``socket.socketpair`` exists on Windows from 3.5 (emulated over loopback TCP),
    so no fallback is needed; wrapped only to keep the call site readable.
    """
    return _socket.socketpair()
