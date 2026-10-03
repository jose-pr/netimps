"""Bounded retry with exponential backoff (internal).

Network calls fail transiently, and the loop that handles that gets rewritten
every time -- usually without jitter, often without a ceiling, occasionally
retrying errors that will never succeed.

Re-exported from :mod:`netimps`.
"""

from __future__ import annotations

import time as _time
from typing import Any, Callable, Iterator, Optional, Tuple, Type

__all__ = ["retry", "backoff_delays", "Backoff"]

#: Exceptions worth retrying by default. ``OSError`` covers the whole socket
#: family (timeout, refused, reset, unreachable, DNS). Deliberately narrow:
#: ``ValueError`` and ``TypeError`` mean the *call* is wrong, and repeating it
#: only wastes the caller's time.
DEFAULT_RETRYABLE: "Tuple[Type[BaseException], ...]" = (OSError,)


def _jittered(
    capped: float,
    max_delay: float,
    jitter: float,
    jitter_seconds: "Optional[float]",
    symmetric: bool,
    random_: "Callable[[], float]",
) -> float:
    """One delay, jittered according to whichever mode is selected.

    Shared by :func:`backoff_delays` and :class:`Backoff` so the three jitter
    shapes are defined once.

    **No mode can return a negative delay. Only the default mode treats
    ``max_delay`` as a ceiling on the final value**, and that difference is
    forced by the specifications the symmetric modes implement. RFC 8415 §15
    applies its jitter *after* the cap -- ``if RT > MRT: RT = MRT + RAND*MRT``
    -- so a conforming delay may exceed ``MRT`` by up to ``RAND``; RFC 2131 §4.1
    likewise randomises +/-1 s around a 64 s maximum. Clamping the symmetric
    modes at ``max_delay`` would leave them one-sided *precisely at the cap*,
    where a backed-off client spends almost all of its time, which reintroduces
    the synchronisation the mode was chosen to prevent. So in the symmetric
    modes ``max_delay`` caps the **base** and the jitter spreads around it.
    """
    if jitter_seconds is not None:
        # Absolute and symmetric: RFC 2131 §4.1 asks for the retransmission
        # delay to be "randomized by the value of a uniform random number
        # chosen from the range -1 to +1" -- seconds, not a fraction.
        #
        # The amplitude is capped at the delay itself so the pre-clamp value
        # cannot go negative. Without that, a delay well below the amplitude
        # (a sub-second timeout in a test) would have much of its distribution
        # clamped to 0, which is neither symmetric nor uniform -- a silently
        # wrong schedule rather than a refused one. For RFC 2131's own
        # schedule the cap never engages: that starts at 4 s against a 1 s
        # amplitude.
        amplitude = min(jitter_seconds, capped)
        value = capped + amplitude * (2.0 * random_() - 1.0)
    elif symmetric and jitter:
        # Proportional and symmetric: RFC 8415 §15 specifies
        # ``RT = 2*RTprev + RAND*RTprev`` with ``RAND`` uniform in [-0.1, +0.1].
        value = capped * (1.0 + jitter * (2.0 * random_() - 1.0))
    elif jitter:
        # The default, and deliberately one-sided -- see `backoff_delays`.
        value = capped - capped * jitter * random_()
        # Upper-clamped, because this mode's whole contract is that
        # `max_delay` is a genuine ceiling: it only ever subtracts, so the
        # clamp is a no-op in practice and kept for the degenerate
        # `capped > max_delay` case.
        return min(max(value, 0.0), max_delay)
    else:
        return capped
    # Symmetric modes: lower bound only. See the note above.
    return max(value, 0.0)


def backoff_delays(
    attempts: int = 3,
    delay: float = 0.5,
    multiplier: float = 2.0,
    max_delay: float = 30.0,
    jitter: float = 0.1,
    *,
    jitter_seconds: "Optional[float]" = None,
    symmetric: bool = False,
    _random=None,
) -> "Iterator[float]":
    """Yield the delay before each retry -- ``attempts - 1`` values.

    Exposed separately so a caller driving its own loop (async, or with
    progress reporting) gets the same schedule without reimplementing it::

        for wait in backoff_delays(attempts=5):
            ...

    :param jitter: fraction of each delay to randomise, spreading retries so
        that many clients failing together do not resynchronise into a
        thundering herd. ``0`` disables it and makes the schedule exact.
    :param jitter_seconds: randomise by an **absolute, symmetric** amount
        instead -- uniform in ``[-jitter_seconds, +jitter_seconds]``, which is
        what **RFC 2131 §4.1** (DHCPv4) specifies. Overrides ``jitter`` when
        set. The amplitude is capped at the current delay so the result cannot
        go negative before clamping; for RFC 2131's own schedule (4 s upward
        against a 1 s amplitude) that cap never engages.
    :param symmetric: make the fractional ``jitter`` spread **both** ways,
        ``delay * (1 ± jitter)``, which is what **RFC 8415 §15** (DHCPv6)
        specifies as ``RT = 2*RTprev + RAND*RTprev``.

    Delays are capped at ``max_delay``. **The default jitter is applied after
    the cap and only ever reduces the wait**, so ``max_delay`` is a genuine
    ceiling -- the right default for generic retries, where overshooting a
    ceiling is worse than a slightly short wait.

    **In the two symmetric modes ``max_delay`` caps the base, not the final
    value**, and a delay may exceed it by up to the jitter amplitude. That is
    what the specifications require: RFC 8415 applies its jitter after the cap
    (``if RT > MRT: RT = MRT + RAND*MRT``) and RFC 2131 randomises +/-1 s
    around its 64 s maximum. Clamping instead would leave those modes one-sided
    exactly at the cap, where a backed-off client spends nearly all of its
    time, which would defeat the point of choosing them. No mode ever returns a
    negative delay.

    For a long-lived session that backs off on loss and **resets on progress**
    -- a retransmission timer rather than a one-shot schedule -- use
    :class:`Backoff` instead.
    """
    if attempts < 1:
        raise ValueError("attempts must be at least 1, got %r" % (attempts,))
    if delay < 0:
        raise ValueError("delay must be non-negative, got %r" % (delay,))
    if not 0 <= jitter <= 1:
        raise ValueError("jitter must be between 0 and 1, got %r" % (jitter,))
    if jitter_seconds is not None and jitter_seconds < 0:
        raise ValueError(
            "jitter_seconds must be non-negative, got %r" % (jitter_seconds,)
        )

    if _random is None:
        import random as _random_module

        _random = _random_module.random

    current = delay
    for _ in range(attempts - 1):
        yield _jittered(
            min(current, max_delay),
            max_delay,
            jitter,
            jitter_seconds,
            symmetric,
            _random,
        )
        current *= multiplier


class Backoff:
    """A retransmission timer: grows on loss, **resets on progress**.

    :func:`backoff_delays` is a one-shot schedule for "retry this call a few
    times". A long-lived session needs the other shape -- a current delay that
    advances when a reply does not come and goes back to the base when the peer
    moves the transfer forward. Every protocol client in this family had
    written its own::

        timer = Backoff(delay=timeout, max_delay=timeout * 8, jitter=0)
        while not done:
            deadline = now() + timer.delay
            if replied:
                timer.reset()          # progress: fresh timer
            elif timer.attempt >= retries:
                raise TransferTimeout(...)
            else:
                timer.advance()        # loss: back off

    ``delay`` is **stable between calls to** :meth:`advance` or :meth:`reset`,
    so arming a deadline, logging it and comparing against it all see one value;
    a property that re-jittered on each read would be a trap here.

    Two guard rails a hand-rolled version tends to miss: ``multiplier`` is
    floored at ``1.0``, so a timer can never *shrink* on loss, and ``max_delay``
    is floored at ``delay``, so a ceiling below the base cannot silently
    truncate the first wait.

    Jitter is **off by default here**, the opposite of
    :func:`backoff_delays`. Its purpose is to desynchronise many clients
    retrying together; a point-to-point session retransmitting to one peer has
    no herd to avoid, and TFTP and TCP both specify plain doubling. Set
    ``jitter``, ``jitter_seconds`` or ``symmetric`` for the protocols that do
    ask for it -- the arguments mean exactly what they mean on
    :func:`backoff_delays`.
    """

    __slots__ = (
        "_base",
        "_multiplier",
        "_max_delay",
        "_jitter",
        "_jitter_seconds",
        "_symmetric",
        "_random",
        "_current",
        "_delay",
        "_attempt",
    )

    def __init__(
        self,
        delay: float = 0.5,
        multiplier: float = 2.0,
        max_delay: float = 30.0,
        jitter: float = 0.0,
        *,
        jitter_seconds: "Optional[float]" = None,
        symmetric: bool = False,
        _random=None,
    ) -> None:
        if delay < 0:
            raise ValueError("delay must be non-negative, got %r" % (delay,))
        if not 0 <= jitter <= 1:
            raise ValueError("jitter must be between 0 and 1, got %r" % (jitter,))
        if jitter_seconds is not None and jitter_seconds < 0:
            raise ValueError(
                "jitter_seconds must be non-negative, got %r" % (jitter_seconds,)
            )
        if _random is None:
            import random as _random_module

            _random = _random_module.random

        self._base = float(delay)
        # Never below 1.0: a "backoff" that shrinks the wait on repeated loss
        # is always a bug, and silently accepting 0.5 would make a session
        # retransmit faster the worse the link got.
        self._multiplier = max(1.0, float(multiplier))
        # Never below the base, so a ceiling set under it cannot truncate the
        # very first wait into something shorter than the caller asked for.
        self._max_delay = max(self._base, float(max_delay))
        self._jitter = jitter
        self._jitter_seconds = jitter_seconds
        self._symmetric = symmetric
        self._random = _random
        self._current = self._base
        self._attempt = 0
        self._delay = self._compute()

    def _compute(self) -> float:
        return _jittered(
            min(self._current, self._max_delay),
            self._max_delay,
            self._jitter,
            self._jitter_seconds,
            self._symmetric,
            self._random,
        )

    @property
    def delay(self) -> float:
        """The wait for the current attempt. Stable until advance/reset."""
        return self._delay

    @property
    def attempt(self) -> int:
        """How many times :meth:`advance` has been called since the last reset."""
        return self._attempt

    def advance(self) -> float:
        """Back off one step and return the new :attr:`delay`."""
        self._current = min(self._current * self._multiplier, self._max_delay)
        self._attempt += 1
        self._delay = self._compute()
        return self._delay

    def reset(self) -> float:
        """Return to the base delay -- the peer made progress."""
        self._current = self._base
        self._attempt = 0
        self._delay = self._compute()
        return self._delay

    def __repr__(self) -> str:
        return "Backoff(delay=%g, attempt=%d, max_delay=%g)" % (
            self._delay,
            self._attempt,
            self._max_delay,
        )


def retry(
    func: "Callable[[], object]",
    attempts: int = 3,
    delay: float = 0.5,
    multiplier: float = 2.0,
    max_delay: float = 30.0,
    jitter: float = 0.1,
    retryable: "Tuple[Type[BaseException], ...]" = DEFAULT_RETRYABLE,
    on_retry: "Optional[Callable[[int, BaseException, float], None]]" = None,
    *,
    jitter_seconds: "Optional[float]" = None,
    symmetric: bool = False,
    _sleep=_time.sleep,
    _random=None,
) -> "Any":
    """Call ``func()``, retrying transient failures with exponential backoff.

    ::

        result = retry(lambda: client.fetch(url))
        result = retry(fetch, attempts=5, delay=1.0)

    Returns whatever ``func`` returns. If every attempt fails, **the last
    exception is re-raised** -- not wrapped -- so the traceback still points at
    the real problem.

    :param retryable: exception types worth another attempt. Defaults to
        ``OSError``, which covers the socket family. **Anything else
        propagates immediately**: a ``ValueError`` means the call is malformed
        and will fail identically next time.
    :param on_retry: called as ``(attempt, exception, next_delay)`` before each
        wait -- the hook for logging, since this deliberately does no logging
        of its own.

    ``attempts`` counts *total* calls, not retries: ``attempts=1`` calls once
    and never sleeps. Delay grows by ``multiplier`` each round, capped at
    ``max_delay``, with ``jitter`` applied to avoid a thundering herd.

    Synchronous by design -- it blocks. For async, drive :func:`backoff_delays`
    from your own loop.
    """
    delays = list(
        backoff_delays(
            attempts=attempts,
            delay=delay,
            multiplier=multiplier,
            max_delay=max_delay,
            jitter=jitter,
            jitter_seconds=jitter_seconds,
            symmetric=symmetric,
            _random=_random,
        )
    )

    for index in range(attempts):
        try:
            return func()
        except retryable as exc:
            if index >= len(delays):
                raise  # last attempt: surface the real error, unwrapped
            wait = delays[index]
            if on_retry is not None:
                on_retry(index + 1, exc, wait)
            if wait:
                _sleep(wait)

    # Unreachable: the loop either returns or raises.
    raise AssertionError("retry loop exited without result")
