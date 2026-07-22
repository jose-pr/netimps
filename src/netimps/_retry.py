"""Bounded retry with exponential backoff (internal).

Network calls fail transiently, and the loop that handles that gets rewritten
every time -- usually without jitter, often without a ceiling, occasionally
retrying errors that will never succeed.

Re-exported from :mod:`netimps`.
"""

from __future__ import annotations

import time as _time
from typing import Callable, Optional, Tuple, Type

__all__ = ["retry", "backoff_delays"]

#: Exceptions worth retrying by default. ``OSError`` covers the whole socket
#: family (timeout, refused, reset, unreachable, DNS). Deliberately narrow:
#: ``ValueError`` and ``TypeError`` mean the *call* is wrong, and repeating it
#: only wastes the caller's time.
DEFAULT_RETRYABLE: "Tuple[Type[BaseException], ...]" = (OSError,)


def backoff_delays(
    attempts: int = 3,
    delay: float = 0.5,
    multiplier: float = 2.0,
    max_delay: float = 30.0,
    jitter: float = 0.1,
    _random=None,
):
    """Yield the delay before each retry -- ``attempts - 1`` values.

    Exposed separately so a caller driving its own loop (async, or with
    progress reporting) gets the same schedule without reimplementing it::

        for wait in backoff_delays(attempts=5):
            ...

    :param jitter: fraction of each delay to randomise, spreading retries so
        that many clients failing together do not resynchronise into a
        thundering herd. ``0`` disables it and makes the schedule exact.

    Delays are capped at ``max_delay``. Jitter is applied *after* the cap and
    only ever reduces the wait, so ``max_delay`` is a genuine ceiling.
    """
    if attempts < 1:
        raise ValueError("attempts must be at least 1, got %r" % (attempts,))
    if delay < 0:
        raise ValueError("delay must be non-negative, got %r" % (delay,))
    if not 0 <= jitter <= 1:
        raise ValueError("jitter must be between 0 and 1, got %r" % (jitter,))

    if _random is None:
        import random as _random_module

        _random = _random_module.random

    current = delay
    for _ in range(attempts - 1):
        capped = min(current, max_delay)
        if jitter:
            capped -= capped * jitter * _random()
        yield capped
        current *= multiplier


def retry(
    func: "Callable[[], object]",
    attempts: int = 3,
    delay: float = 0.5,
    multiplier: float = 2.0,
    max_delay: float = 30.0,
    jitter: float = 0.1,
    retryable: "Tuple[Type[BaseException], ...]" = DEFAULT_RETRYABLE,
    on_retry: "Optional[Callable[[int, BaseException, float], None]]" = None,
    _sleep=_time.sleep,
    _random=None,
):
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
