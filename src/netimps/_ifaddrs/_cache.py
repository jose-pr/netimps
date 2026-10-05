"""Choosing the enumerator, counting enumerations, and the shared TTL cache."""

from __future__ import annotations

import logging as _logging
import sys as _sys
import threading as _threading
import time as _time
from typing import Dict, List, Tuple, Union
from ._fallback import _fallback_interfaces
from ._model import Interface
from ._posix import _posix_interfaces
from ._windows import _windows_interfaces

_log = _logging.getLogger("netimps._ifaddrs")


_IS_WINDOWS = _sys.platform == "win32"


#: Default lifetime for a cached enumeration, in seconds, used by ``cache=True``.
#:
#: **One second, because this cache exists to collapse a burst of back-to-back
#: calls** -- resolving the arrival interface of every datagram in a flood, or
#: walking a list of addresses -- not to hold a long-lived snapshot. At a
#: measured 0.98 ms per enumeration that bounds the cost at one syscall per
#: second whatever the arrival rate: roughly 0.1% overhead at 1000 packets per
#: second, against a 97x saving on each individual call. A longer default would
#: buy almost nothing more and would widen the window in which the answer is
#: wrong.
#:
#: :class:`netimps.UDPEndpoint` builds its arrival-interface index from this
#: cache with this same constant, so there is one number rather than two that
#: can disagree. Pass a number to choose your own, and prefer ``cache=math.inf``
#: plus :func:`clear_interface_cache` when you know the moment it changes.
INTERFACE_CACHE_TTL = 1.0

_CACHE_LOCK = _threading.Lock()
#: Bumped by :func:`clear_interface_cache`. An enumeration stores its result
#: only if no clear happened since it began.
_GENERATION = 0
#: Whether the fallback has been logged: once is enough.
_fallback_logged = False
#: ``raw`` flag -> (monotonic stamp, interfaces). Keyed by ``raw`` because the two
#: return different data and sharing one entry would hand a caller the wrong shape.
_INTERFACE_CACHE: "Dict[bool, Tuple[float, List[Interface]]]" = {}


def clear_interface_cache() -> None:
    """Drop any cached enumeration, so the next cached call re-enumerates.

    For a caller that *knows* the adapter set changed -- it bound a socket,
    watched netlink, or handled ``WM_NETWORKCHANGE`` -- and should not wait out
    the TTL. Harmless when nothing is cached.
    """
    global _GENERATION
    with _CACHE_LOCK:
        _GENERATION += 1
        _INTERFACE_CACHE.clear()


_ENUMERATIONS = 0


def interface_enumerations() -> int:
    """How many times this process has really enumerated its adapters.

    Monotonic, and counts only the **syscall**, never a cached hit -- which is
    the point: with ``cache=`` a lookup and an enumeration stop being the same
    event, and the enumeration is the one a packet flood multiplies. A test
    reads it either side of the code under test::

        before = interface_enumerations()
        for _ in range(20):
            get_interface(address, cache=True)
        assert interface_enumerations() - before == 1

    It is also worth exporting as a metric: how often a long-running server
    re-reads its adapters answers whether its cache is sized right.

    Both ``raw=True`` and ``raw=False`` count into this one total. The cache is
    keyed by ``raw``, so a process using both pays two enumerations to warm up
    and will see this advance twice.

    :func:`clear_interface_cache` does not advance it -- dropping a cache
    enumerates nothing by itself; the next cached call is what pays.
    """
    return _ENUMERATIONS


def _enumerate_interfaces(raw: bool) -> "List[Interface]":
    global _ENUMERATIONS

    # Counted under the cache lock rather than bare, because `+= 1` on an int is
    # not atomic and this is the one number a caller may be asserting on. The
    # lock is held for the increment only, never across the syscall below, which
    # would serialise every thread behind the slowest platform call.
    with _CACHE_LOCK:
        _ENUMERATIONS += 1

    global _fallback_logged
    try:
        if _IS_WINDOWS:
            return _windows_interfaces(raw)
        return _posix_interfaces(raw)
    except OSError as exc:
        # Only "the platform would not answer" degrades. A defect in the walk
        # (a bad pointer, a missing symbol) raises and is not mistaken for a
        # host with one interface.
        if not _fallback_logged:
            _fallback_logged = True
            _log.debug(
                "native interface enumeration failed, using hostname lookup: %s", exc
            )
        return _fallback_interfaces(raw, exc)


def _copy_interfaces(found: "List[Interface]") -> "List[Interface]":
    """The cached interfaces as the caller's own list.

    An :class:`Interface` is immutable all the way down, ``raw`` included, so
    the stored objects are handed out as they are.
    """
    return list(found)


def get_interfaces(
    *,
    raw: bool = False,
    cache: "Union[bool, float]" = False,
) -> "List[Interface]":
    """Return this host's network interfaces.

    Uses ``getifaddrs(3)`` on POSIX and ``GetAdaptersAddresses`` on Windows via
    :mod:`ctypes` -- no third-party dependency -- so adapter names, MACs and
    real prefix lengths are all available::

        for iface in get_interfaces():
            print(iface.name, iface.mac, [str(ip) for ip in iface.ips])

    :param raw: when True, populate :attr:`Interface.raw` with the untouched
        platform data (Linux/BSD ``flags``; Windows adapter ``guid``,
        ``if_type``, ...). **Not portable** -- outside the stability guarantee.
    :param cache: reuse a recent enumeration instead of making the syscall.
        ``False`` (the default) never caches and never reads a cached value, so
        every call enumerates afresh. ``True`` uses
        :data:`INTERFACE_CACHE_TTL` seconds, and a number is that TTL in
        seconds -- so **``cache=0`` enumerates now and reseeds the cache**, a
        TTL of zero being always stale. That is the only "force a refresh"
        anyone needs, which is why there is no second argument for it;
        :func:`clear_interface_cache` covers invalidating without a lookup.

        The cache is process-wide and shared with
        :func:`netimps.get_interface`, :func:`netimps.iter_interfaces` and
        :func:`netimps.is_local_address`, which all take the same argument.

    **Opt-in on purpose.** Enumeration is a syscall, and on a host with many
    adapters a measured 35-42 ms of one, so a per-packet caller needs a cache;
    but an adapter set changes under you, and silently answering from a stale
    snapshot by default would turn a cheap call into a wrong one. The caller
    knows which it wants.

    **Prefer an event to a TTL when you have one.** A TTL is a guess about how
    long the answer stays true; if your program already knows the moment it can
    change, say so instead::

        get_interfaces(cache=math.inf)   # never expires on its own
        ...
        clear_interface_cache()          # at the moment it can change

    That is strictly better than any TTL: no window of wrong answers, and no
    re-enumeration while nothing has changed. A server binding its sockets has
    exactly such a moment, since binding is when the set of addresses it serves
    can change.

    A TTL (``cache=True``, or a number) is for the caller with no such moment --
    a loop making many calls in a row that just wants to stop paying for every
    one, and can tolerate :data:`INTERFACE_CACHE_TTL` of staleness.

    Enumerating per datagram is not merely slow: at 35-42 ms it is slow enough
    that a packet flood can deny service on its own.

    **A cached call returns the same immutable objects, in a fresh list.**
    ``Interface`` cannot change after construction, ``ips`` is a tuple and
    ``raw`` a read-only mapping, so one caller cannot corrupt another's view.
    :func:`clear_interface_cache` also discards the result of an enumeration
    that was already running when it was called.

    Does not raise when the platform will not answer (an ``OSError`` from the
    native call): it degrades to a hostname-resolution fallback in which
    prefixes are *not* real (every address becomes a ``/32``/``/128`` under an
    interface named ``"<unknown>"``, with the reason in ``raw`` and logged once
    at debug). A degraded result is cached like any other -- it is the honest
    answer for as long as the native call keeps failing. Any other exception is
    a defect and propagates.
    """
    if cache is False:
        return _enumerate_interfaces(raw)

    # `is True` rather than truthiness, and the distinction carries weight:
    # `cache=1` is a one-second TTL rather than the default one, and `cache=0`
    # is "always stale" -- enumerate and store -- rather than "do not cache".
    # That last case is what a caller means by "refresh", so it needs no
    # argument of its own.
    ttl = INTERFACE_CACHE_TTL if cache is True else float(cache)
    return _copy_interfaces(_interface_snapshot(raw, ttl)[1])


def _interface_snapshot(raw: bool, ttl: float) -> "Tuple[float, List[Interface]]":
    """The shared enumeration no older than ``ttl`` seconds, and when it began.

    Returns ``(monotonic stamp, interfaces)``. The list is the cache's own and
    must not be mutated. The stamp lets a caller that derives its own index
    from the snapshot age it from the enumeration, not from the derivation.
    """
    with _CACHE_LOCK:
        entry = _INTERFACE_CACHE.get(bool(raw))
        if entry is not None and (_time.monotonic() - entry[0]) < ttl:
            return entry
        generation = _GENERATION
    started = _time.monotonic()

    # Enumerated outside the lock: it is a syscall, and holding a lock across it
    # would serialise every thread behind the slowest platform call. Two threads
    # racing here duplicate the work once and then agree, which is cheaper than
    # the contention.
    found = _enumerate_interfaces(raw)
    with _CACHE_LOCK:
        # Stamped when the enumeration began, and dropped if the cache was
        # cleared meanwhile: the snapshot predates whatever the clear was for.
        if _GENERATION == generation:
            _INTERFACE_CACHE[bool(raw)] = (started, found)
    return started, found
