"""``netimps mtu``: the path MTU to a destination."""

from __future__ import annotations

import typing as _ty

from duho import Choice

from netimps import discover_mtu, get_pmtu, get_tcp_mss

from ._common import FOUND, NONE, Command, guarded


class Mtu(Command):
    """Measure the path MTU to a destination."""

    _parsername_ = "mtu"

    dst: str
    "Destination to measure toward"
    ("dst",)

    method: _ty.Annotated[str, Choice("icmp", "udp", "tcp")] = "icmp"
    "How to probe; tcp derives from the negotiated MSS"
    ("--method", "-m")

    port: int = 80
    "Port for --method udp/tcp"
    ("--port", "-p")

    timeout: float = 1.0
    "Seconds per probe"
    ("--timeout", "-t")

    cached: bool = False
    "Only report the kernel's cached answer; do not probe"
    ("--cached",)

    @guarded
    def __call__(self) -> int:
        value = self.measure()
        payload: "_ty.Dict[str, _ty.Any]" = {
            "dst": self.dst,
            "mtu": value,
            "method": "cached" if self.cached else self.method,
        }
        if self.method == "tcp" and not self.cached:
            payload["mss"] = get_tcp_mss(self.dst, self.port)
        if value is None:
            line = "%s: no answer -- the destination may filter probes" % self.dst
        else:
            line = "%s: MTU %d bytes (%s)" % (self.dst, value, payload["method"])
        self.emit(payload, line)
        return FOUND if value is not None else NONE

    def measure(self) -> "_ty.Optional[int]":
        if self.cached:
            return get_pmtu(self.dst, self.port)
        return discover_mtu(
            self.dst,
            timeout=self.timeout,
            port=self.port,
            method=_ty.cast("_ty.Literal['icmp', 'tcp', 'udp']", self.method),
        )
