"""``PingResult``: the outcome of a ping, truthy when it succeeded."""

from __future__ import annotations

from functools import partial as _partial
from typing import Any, Optional, Tuple
from .._ip import HostLike, IPAddress


class PingResult:
    """Outcome of a :func:`ping`, usable directly as a boolean.

    ``ping()`` answers "did it reply?", so this is truthy on success and falsy
    on failure -- ``if ping(host):`` works -- while carrying the details a
    caller would otherwise re-run ``ping`` to scrape.

    Attributes:
        ok: whether the destination replied.
        dst: the destination as given.
        rtt: round-trip time in seconds, or ``None`` if not reported.
            Sub-millisecond replies (``time<1ms``) are recorded as ``0.0``,
            which is falsy -- test ``is None`` rather than truthiness.
        ttl: TTL/hop-limit of the reply, or ``None``. Counts *down* from the
            sender's initial value, so a smaller number means more hops.
        src: address that answered, which on success is the destination.
        attempts: how many probes were sent before this outcome.
    """

    __slots__ = ("ok", "dst", "rtt", "ttl", "src", "attempts")

    ok: bool
    dst: "HostLike"
    rtt: Optional[float]
    ttl: Optional[int]
    src: "Optional[IPAddress]"
    attempts: int

    def __init__(
        self,
        ok: bool,
        dst: "HostLike",
        *,
        rtt: Optional[float] = None,
        ttl: Optional[int] = None,
        src: "Optional[IPAddress]" = None,
        attempts: int = 1,
    ) -> None:
        object.__setattr__(self, "ok", ok)
        object.__setattr__(self, "dst", dst)
        object.__setattr__(self, "rtt", rtt)
        object.__setattr__(self, "ttl", ttl)
        object.__setattr__(self, "src", src)
        object.__setattr__(self, "attempts", attempts)

    def __reduce__(self) -> "Tuple[Any, Tuple[Any, ...]]":
        """Pickle and copy through the constructor.

        ``__slots__`` plus a blocked ``__setattr__`` defeats the default
        restore, which assigns the slots back onto a blank instance.
        """
        return (
            _partial(
                PingResult,
                self.ok,
                self.dst,
                rtt=self.rtt,
                ttl=self.ttl,
                src=self.src,
                attempts=self.attempts,
            ),
            (),
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("PingResult is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("PingResult is immutable")

    def __bool__(self) -> bool:
        return bool(self.ok)

    def __repr__(self) -> str:
        return "PingResult(ok=%r, dst=%r, rtt=%r, ttl=%r)" % (
            self.ok,
            self.dst,
            self.rtt,
            self.ttl,
        )

    def __eq__(self, other: object) -> bool:
        # Compares equal to a plain bool so existing `== True` assertions and
        # boolean-returning call sites keep behaving.
        if isinstance(other, bool):
            return bool(self) is other
        if isinstance(other, PingResult):
            return (
                self.ok == other.ok
                and self.dst == other.dst
                and self.rtt == other.rtt
                and self.ttl == other.ttl
            )
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.ok, self.dst, self.rtt, self.ttl))
