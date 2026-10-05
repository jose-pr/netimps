"""``netimps ping``: does a host answer, by ICMP, TCP or UDP."""

from __future__ import annotations

import typing as _ty

from duho import Choice

from netimps import PingResult, ping

from ._common import FOUND, NONE, Command, guarded


class Ping(Command):
    """Check whether a host answers, by ICMP, TCP or UDP."""

    _parsername_ = "ping"

    # No default: a missing host must be argparse's "required argument"
    # message, not a ping of the empty string reported as unreachable.
    dst: str
    "Host to ping"
    ("dst",)

    method: _ty.Annotated[str, Choice("icmp", "tcp", "udp")] = "icmp"
    "Probe type; tcp/udp reach hosts that drop ICMP echo"
    ("--method", "-m")

    port: _ty.Optional[int] = None
    "Port for --method tcp/udp"
    ("--port", "-p")

    count: int = 1
    "Attempts before giving up"
    ("--count", "-c")

    timeout: float = 1.0
    "Seconds to wait per attempt"
    ("--timeout", "-t")

    size: _ty.Optional[int] = None
    "ICMP payload bytes (the wire packet is larger by the headers)"
    ("--size", "-s")

    source: _ty.Optional[str] = None
    "Send from this interface, address or MAC"
    ("--source", "-S")

    @guarded
    def __call__(self) -> int:
        result = self.probe()
        # The result carries seconds; the command's output is in milliseconds.
        rtt_ms = None if result.rtt is None else result.rtt * 1000.0
        self.emit(self.payload(result, rtt_ms), self.line(result, rtt_ms))
        return FOUND if result.ok else NONE

    def probe(self) -> PingResult:
        return ping(
            self.dst,
            tries=self.count,
            timeout=self.timeout,
            method=_ty.cast("_ty.Literal['icmp', 'tcp', 'udp']", self.method),
            port=self.port,
            size=self.size,
            src=self.source,
        )

    def payload(self, result: PingResult, rtt_ms: "_ty.Optional[float]") -> "_ty.Any":
        return {
            "ok": result.ok,
            "host": result.dst,
            "rtt_ms": rtt_ms,
            "ttl": result.ttl,
            "attempts": result.attempts,
            "method": self.method,
        }

    def line(self, result: PingResult, rtt_ms: "_ty.Optional[float]") -> str:
        if not result.ok:
            return "%s did not answer (%s)" % (self.dst, self.method)
        ttl = "" if result.ttl is None else ", ttl %d" % result.ttl
        return "%s is up (%s, %.2f ms%s)" % (
            self.dst,
            self.method,
            rtt_ms if rtt_ms is not None else float("nan"),
            ttl,
        )
