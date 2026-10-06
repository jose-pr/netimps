"""``await_for_port``: :func:`wait_for_port` as a coroutine, a connect on the running loop."""

from __future__ import annotations

import socket as _socket
from typing import Any, List, Optional, Tuple
from .._ip import HostLike, _dst_argument
from .._scheme import coerce_port as _coerce_port
from ._connect import _connect_timeout

_FAILURES = (OSError, UnicodeError, ValueError, OverflowError)


async def _infos(
    loop: Any, dst: str, port: int, remaining: "Optional[float]"
) -> "List[Tuple[Any, ...]]":
    """``getaddrinfo`` results for ``dst``, or ``[]`` when nothing resolves.

    An address literal is read in place, with no lookup and no thread. A name
    goes through ``loop.getaddrinfo``, which asyncio runs on its own executor:
    a blocking lookup on the loop would stall every other task.
    """
    import asyncio

    try:
        return _socket.getaddrinfo(
            dst, port, 0, _socket.SOCK_STREAM, 0, _socket.AI_NUMERICHOST
        )
    except _FAILURES:
        pass  # not a literal
    try:
        lookup = loop.getaddrinfo(dst, port, type=_socket.SOCK_STREAM)
        if remaining is None:
            return await lookup
        return await asyncio.wait_for(lookup, remaining)
    except _FAILURES + (asyncio.TimeoutError,):
        return []


async def _tcp_check(
    loop: Any, dst: "HostLike", port: int, timeout: "Optional[float]"
) -> bool:
    """:func:`tcp_check` on the running loop: the same answers, bounded the same way."""
    import asyncio

    host = _dst_argument(dst)
    number = _coerce_port(port)
    budget = _connect_timeout(timeout)
    expires = None if budget is None else loop.time() + budget

    def left() -> "Optional[float]":
        return None if expires is None else expires - loop.time()

    infos = await _infos(loop, host, number, left())
    for family, kind, proto, _canon, sockaddr in infos:
        remaining = left()
        if remaining is not None and remaining <= 0:
            return False
        try:
            sock = _socket.socket(family, kind, proto)
        except OSError:
            continue
        try:
            sock.setblocking(False)
            await asyncio.wait_for(loop.sock_connect(sock, sockaddr), remaining)
            return True
        except _FAILURES + (asyncio.TimeoutError,):
            continue
        finally:
            # Also on cancellation: the connect is cancelled before this runs, so
            # nothing is left registered on the loop for a closed descriptor.
            sock.close()
    return False


async def await_for_port(
    dst: "HostLike",
    port: int,
    *,
    deadline: float = 30.0,
    interval: float = 0.1,
    timeout: Optional[float] = None,
) -> bool:
    """:func:`wait_for_port` as a coroutine: poll until ``dst``:``port`` accepts.

    ::

        if not await await_for_port("localhost", 5432, deadline=60):
            raise RuntimeError("database never started")

    Every argument means what it means on :func:`wait_for_port`, and so do the
    ``True`` and ``False`` it returns and the :class:`ValueError` for a ``port``
    out of range. Each attempt is a non-blocking connect on the running loop and
    each wait is ``asyncio.sleep``, so the loop keeps running and no thread is
    used for an address literal; a name is looked up with ``loop.getaddrinfo``,
    which uses the loop's executor. Cancelling the task closes the socket of the
    attempt in progress and leaves nothing behind.

    The ``deadline`` is a ceiling on the whole wait: an attempt is given no more
    than what is left of it, so the call returns within a small fraction of a
    second after ``deadline`` whatever the connect is doing.
    """
    import asyncio

    loop = asyncio.get_running_loop()
    expires = loop.time() + deadline
    per_try = timeout if timeout is not None else max(interval, 1.0)
    delay = interval

    while True:
        remaining = expires - loop.time()
        if remaining <= 0:
            return False
        if await _tcp_check(loop, dst, port, min(per_try, remaining)):
            return True
        remaining = expires - loop.time()
        if remaining <= 0:
            return False
        await asyncio.sleep(min(delay, remaining))
        # Backing off never shortens the interval the caller asked for.
        delay = min(delay * 1.5, max(interval, 1.0))
