"""``netimps check``: does a TCP port accept a connection."""

from __future__ import annotations

import typing as _ty

from netimps import get_default_port, tcp_check, wait_for_port

from ._common import ERROR, FOUND, NONE, Command, error, guarded


class Check(Command):
    """Test whether a TCP port accepts a connection."""

    _parsername_ = "check"
    _parseraliases_ = ["tcp"]

    dst: str
    "Host to connect to"
    ("dst",)

    port: str
    "Port number or scheme name (https, ssh, ...)"
    ("port",)

    timeout: float = 3.0
    "Connect timeout in seconds"
    ("--timeout", "-t")

    wait: _ty.Optional[float] = None
    "Poll until it answers, up to this many seconds"
    ("--wait", "-w")

    @guarded
    def __call__(self) -> int:
        port = get_default_port(self.port)
        if port is None:
            # A port the command cannot derive is a caller error, not a closed
            # port: nothing was tested.
            error("error: unknown port or scheme %r" % self.port)
            return ERROR
        ok = self.connect(port)
        self.emit(
            {"ok": ok, "host": self.dst, "port": port},
            "%s:%d is %s" % (self.dst, port, "open" if ok else "closed"),
        )
        return FOUND if ok else NONE

    def connect(self, port: int) -> bool:
        if self.wait is not None:
            return wait_for_port(self.dst, port, deadline=self.wait)
        return tcp_check(self.dst, port, timeout=self.timeout)
